// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![allow(deprecated)]

extern crate mio;
extern crate rust_sodium;

extern crate bytes;
extern crate clap;
extern crate crust;
extern crate future_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate p2p;
extern crate p2p_old;
extern crate safe_crypto;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_timer;
#[macro_use]
extern crate unwrap;

mod common;

use bytes::Bytes;
use clap::{App, Arg};
use common::event_loop::{spawn_event_loop, El};
use common::{LogUpdate, NatTraversalResult, Os, Rpc};
use crust::{ConfigFile, CrustError, CrustUser, Service};
use future_utils::mpsc::SendError;
use futures::sync::mpsc::{self, UnboundedSender};
use futures::{future::empty, Future, Sink, Stream};
use maidsafe_utilities::{
    log as logger,
    serialisation::{deserialise, serialise, SerialisationError},
};
use mio::Poll;
use p2p_old::{
    Handle as P2pHandle, HolePunchInfo, HolePunchMediator, Interface, NatError, NatMsg,
    RendezvousInfo, Res,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::process;
use std::rc::Rc;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};
use tokio_core::reactor::{Core, Handle};
use tokio_timer::Delay;

pub type PublicEncryptKey = [u8; 32];

const RETRY_DELAY: u64 = 10;

#[derive(Debug)]
pub enum Error {
    Crust(CrustError),
    Unexpected(String),
    Serialisation(SerialisationError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ::std::error::Error for Error {}

impl<T> From<SendError<T>> for Error {
    fn from(err: SendError<T>) -> Self {
        Error::Unexpected(format!("{}", err))
    }
}

impl From<CrustError> for Error {
    fn from(err: CrustError) -> Self {
        Error::Crust(err)
    }
}

impl From<SerialisationError> for Error {
    fn from(err: SerialisationError) -> Self {
        Error::Serialisation(err)
    }
}

impl From<String> for Error {
    fn from(string: String) -> Self {
        Error::Unexpected(string)
    }
}

#[derive(Debug)]
enum Msg {
    Incoming(Rpc),
    RetryConnect,
    Terminate,
    ConnectedWithPeer(PublicEncryptKey, Result<FullConnStats, ()>, bool),
}

/// Detects OS type
pub fn detect_os() -> Os {
    if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Unknown
    }
}

fn retry_connection(handle: &Handle, tx: &UnboundedSender<Msg>) {
    let tx2 = tx.clone();
    handle.spawn(
        Delay::new(Instant::now() + Duration::from_secs(RETRY_DELAY))
            .and_then(move |_| {
                unwrap!(tx2.unbounded_send(Msg::RetryConnect));
                Ok(())
            }).map_err(|e| panic!("Delay error: {:?}", e)),
    );
}

#[derive(Debug)]
struct ConnStats {
    our: Option<SocketAddr>,
    their: Option<SocketAddr>,
}

#[derive(Debug)]
struct FullConnStats {
    tcp: Option<ConnStats>,
    udp: Option<ConnStats>,
}

struct Client {
    handle: Handle,
    proxy_tx: UnboundedSender<Bytes>,
    client_tx: UnboundedSender<Msg>,
    service: Rc<RefCell<Service>>,
    successful_conns: Vec<PublicEncryptKey>,
    attempted_conns: Vec<PublicEncryptKey>,
    failed_conns: Vec<PublicEncryptKey>,
    connecting_to: Option<PublicEncryptKey>,
    our_id: PublicEncryptKey,
    our_ci: Option<RendezvousInfo>,
    p2p_handle: Option<P2pHandle>,
    name: Option<String>,
    peer_names: HashMap<PublicEncryptKey, String>,
    p2p_el: El,
}

impl Client {
    fn new(
        our_id: PublicEncryptKey,
        name: Option<String>,
        service: Service,
        handle: Handle,
        proxy_tx: UnboundedSender<Bytes>,
        client_tx: UnboundedSender<Msg>,
        p2p_el: El,
    ) -> Self {
        Client {
            our_id,
            handle,
            proxy_tx,
            client_tx,
            name,
            p2p_handle: None,
            peer_names: Default::default(),
            service: Rc::new(RefCell::new(service)),
            successful_conns: Vec::new(),
            attempted_conns: Vec::new(),
            failed_conns: Vec::new(),
            connecting_to: None,
            our_ci: None,
            p2p_el,
        }
    }

    fn report_connection_result(
        &mut self,
        peer_id: PublicEncryptKey,
        conn_res: Result<FullConnStats, ()>,
        send_stats: bool,
    ) -> Result<(), Error> {
        let is_successful = conn_res.is_ok();

        if is_successful {
            self.successful_conns.push(peer_id);
        } else {
            self.failed_conns.push(peer_id);
        }

        info!(
            "SuccessfulConns: {:?}",
            self.successful_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        );
        info!(
            "FailedConns: {:?}",
            self.failed_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        );
        info!(
            "AttemptedConns: {:?}",
            self.attempted_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        );

        // Connected to peer
        info!(
            "!!! {} with {} !!!",
            if is_successful {
                "Sucessfully connected"
            } else {
                "Failed to connect"
            },
            self.get_peer_name(peer_id),
        );

        if let Ok(FullConnStats { ref tcp, .. }) = conn_res {
            info!(
                "TCP result: {}",
                if let Some(tcp) = tcp {
                    format!(
                        "{} (us) <-> {} (them)",
                        tcp.our
                            .map(|ip| format!("{}", ip))
                            .unwrap_or_else(|| "None".to_string()),
                        tcp.their
                            .map(|ip| format!("{}", ip))
                            .unwrap_or_else(|| "None".to_string())
                    )
                } else {
                    "Failed".to_owned()
                }
            );
        }
        if let Ok(FullConnStats { ref udp, .. }) = conn_res {
            info!(
                "UDP result: {}",
                if let Some(udp) = udp {
                    format!(
                        "{} (us) <-> {} (them)",
                        udp.our
                            .map(|ip| format!("{}", ip))
                            .unwrap_or_else(|| "None".to_string()),
                        udp.their
                            .map(|ip| format!("{}", ip))
                            .unwrap_or_else(|| "None".to_string())
                    )
                } else {
                    "Failed".to_owned()
                }
            );
        }

        // Send stats only if the requester is us
        if send_stats {
            let log_upd = self.aggregate_stats(peer_id, conn_res);
            info!("Sending stats {:?}", log_upd);
            self.send_rpc(&Rpc::UploadLog(log_upd))?;
        }

        Ok(())
    }

    fn probe_nat(&self, el: &mut Core) -> Result<(), Error> {
        let nat_type = unwrap!(el.run(self.service.borrow().probe_nat()));
        // let nat_type = NatType::Unknown;
        let os_type = detect_os();
        info!("Detected NAT type {:?}", nat_type);
        info!("Detected OS type: {:?}", os_type);

        // Send the NAT type to the bootstrap proxy
        self.send_rpc(&Rpc::UpdateDetails {
            name: self.name.clone(),
            nat: nat_type,
            os: os_type,
        })
    }

    fn aggregate_stats(
        &self,
        peer: PublicEncryptKey,
        conn_res: Result<FullConnStats, ()>,
    ) -> LogUpdate {
        let mut tcp_hole_punch_result = NatTraversalResult::Failed;
        let mut udp_hole_punch_result = NatTraversalResult::Failed;

        if let Ok(res) = conn_res {
            if res.tcp.is_some() {
                tcp_hole_punch_result = NatTraversalResult::Succeeded
            };
            if res.udp.is_some() {
                udp_hole_punch_result = NatTraversalResult::Succeeded
            };
        }

        LogUpdate {
            peer,
            udp_hole_punch_result,
            tcp_hole_punch_result,
        }
    }

    fn send_rpc(&self, rpc: &Rpc) -> Result<(), Error> {
        info!("Sending {}", rpc);
        let bytes = serialise(&rpc)?;
        self.proxy_tx.unbounded_send(Bytes::from(bytes))?;
        Ok(())
    }

    fn get_peer_name(&self, id: PublicEncryptKey) -> String {
        if let Some(name) = self.peer_names.get(&id) {
            format!("{} ({:?})", name, id)
        } else {
            format!("{:?}", id)
        }
    }

    fn handle_new_message(&mut self, rpc_cmd: Rpc) -> Result<(), Error> {
        info!("Received {}", rpc_cmd);

        match rpc_cmd {
            Rpc::GetPeerResp(name, ci_opt) => {
                if let Some(mut ci) = ci_opt {
                    // Attempt to connect with peer
                    self.attempted_conns.push(ci.enc_pk);
                    if let Some(name) = name {
                        self.peer_names.insert(ci.enc_pk, name.clone());
                    }
                    self.connecting_to = Some(ci.enc_pk);
                    info!(
                        "Attempting to connect with {}...",
                        self.get_peer_name(ci.enc_pk)
                    );

                    let id = ci.enc_pk;
                    let client_tx = self.client_tx.clone();
                    let our_ci = unwrap!(self.our_ci.take());

                    unwrap!(self.p2p_handle.take()).fire_hole_punch(
                        ci,
                        Box::new(move |_, _, res| {
                            // Hole punch success
                            let full_stats = collect_conn_result(&our_ci, res);

                            unwrap!(
                                client_tx
                                    .unbounded_send(Msg::ConnectedWithPeer(id, full_stats, true))
                            );

                            unwrap!(client_tx.unbounded_send(Msg::RetryConnect));
                        }),
                    );
                } else {
                    // Retry again in some time
                    info!(
                        "All available peers have been attempted to be reached. Checking for new peers in {} seconds",
                        RETRY_DELAY
                    );
                    retry_connection(&self.handle, &self.client_tx);
                }
            }
            Rpc::GetPeerReq(name, theirs_ci) => {
                // Someone requested a direct connection with us
                let theirs_id = theirs_ci.enc_pk;
                if let Some(name) = name {
                    self.peer_names.insert(theirs_id, name.clone());
                }
                self.attempted_conns.push(theirs_id);

                info!(
                    "Attempting to connect with {}...",
                    self.get_peer_name(theirs_id)
                );

                let client_tx = self.client_tx.clone();;
                let name = self.name.clone();

                let (handle, mut our_ci) = unwrap!(get_rendezvous_info(&self.p2p_el));
                our_ci.enc_pk = self.our_id;
                trace!("Our responder CI: {:?}", our_ci);

                let our_ci2 = our_ci.clone();

                handle.fire_hole_punch(
                    theirs_ci,
                    Box::new(move |_, _, res| {
                        // Hole punch success
                        let full_stats = collect_conn_result(&our_ci2, res);

                        unwrap!(
                            client_tx.unbounded_send(Msg::ConnectedWithPeer(
                                theirs_id, full_stats, false
                            ))
                        );
                    }),
                );

                self.send_rpc(&Rpc::GetPeerResp(name, Some(our_ci)))?;
            }
            _ => {
                error!("Invalid command from the proxy");
            }
        }

        Ok(())
    }

    fn await_peer(&mut self) -> Result<(), Error> {
        let (handle, mut our_ci) = unwrap!(get_rendezvous_info(&self.p2p_el));
        our_ci.enc_pk = self.our_id;
        trace!("Our requester CI: {:?}", our_ci);

        self.p2p_handle = Some(handle);
        self.our_ci = Some(our_ci.clone());

        self.send_rpc(&Rpc::GetPeerReq(self.name.clone(), our_ci))?;

        Ok(())
    }
}

fn collect_conn_result(
    our_ci: &RendezvousInfo,
    conn_res: Result<HolePunchInfo, NatError>,
) -> Result<FullConnStats, ()> {
    let HolePunchInfo { tcp, udp, .. } = match conn_res {
        Ok(conn_info) => conn_info,
        Err(_e) => {
            // could not traverse nat type
            return Err(());
        }
    };

    let tcp = if let Some((tcp_stream, _tcp_token)) = tcp {
        Some(ConnStats {
            our: Some(unwrap!(our_ci.tcp)),
            their: Some(unwrap!(tcp_stream.peer_addr())),
        })
    } else {
        None
    };

    let udp = if let Some((_udp_sock, udp_peer, udp_our_ext_addr, _udp_token)) = udp {
        Some(ConnStats {
            our: Some(udp_our_ext_addr),
            their: Some(udp_peer),
        })
    } else {
        None
    };

    Ok(FullConnStats { tcp, udp })
}

fn get_user_name() -> Option<String> {
    print!("Please enter your name (or press Enter if you don't want any): ");
    unwrap!(io::stdout().flush());

    let stdin = io::stdin();
    let mut our_name = String::new();
    unwrap!(stdin.lock().read_line(&mut our_name));
    let our_name = our_name.trim().to_string();

    if our_name.is_empty() {
        None
    } else {
        Some(our_name)
    }
}

fn get_rendezvous_info(el: &El) -> Res<(p2p_old::Handle, RendezvousInfo)> {
    let (tx, rx) = std_mpsc::channel();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let get_info = move |_: &mut Interface, _: &Poll, res| {
            unwrap!(tx.send(res));
        };
        unwrap!(HolePunchMediator::start(ifc, poll, Box::new(get_info)));
    })));

    unwrap!(rx.recv())
}

fn main() {
    unwrap!(logger::init(true));

    let matches = App::new("Crust Client Example")
        .author("MaidSafe Developers <dev@maidsafe.net>")
        .about("Connects to the bootstrap matching server")
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .takes_value(true)
                .help("Config file path"),
        ).arg(
            Arg::with_name("prevent_direct")
                .long("prevent-direct-connections")
                .help("Prevents direct connections requiring the other side to hole punch"),
        ).get_matches();

    let our_name = get_user_name();

    let config = unwrap!(if let Some(cfg_path) = matches.value_of("config") {
        info!("Loading config from {}", cfg_path);
        ConfigFile::open_path(From::from(cfg_path))
    } else {
        ConfigFile::open_default()
    });

    let p2p_el = spawn_event_loop();

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();

    let (our_pk, our_sk) = safe_crypto::gen_encrypt_keypair();
    let mut svc = unwrap!(event_loop.run(Service::with_config(&handle, config, our_sk, our_pk)));

    info!("Our public ID: {}", our_pk);

    info!("Attempting bootstrap...");
    let proxy =
        unwrap!(event_loop.run(svc.bootstrap(Default::default(), false, CrustUser::Client)));
    info!(
        "Connected to {}, {}",
        proxy.public_id(),
        unwrap!(proxy.addr())
    );

    let (proxy_sink, proxy_stream) = proxy.split();
    let (proxy_tx, proxy_rx) = mpsc::unbounded();

    let (client_tx, client_rx) = mpsc::unbounded();
    let client_tx2 = client_tx.clone();
    let client_tx3 = client_tx.clone();

    // Setup listeners
    let listeners = unwrap!(event_loop.run(svc.start_listening().collect()));
    for listener in &listeners {
        info!("Listening on {}", listener.addr());
    }

    let mut client = Client::new(
        our_pk.into_bytes(),
        our_name,
        svc,
        handle.clone(),
        proxy_tx.clone(),
        client_tx.clone(),
        p2p_el,
    );

    // Transfer bytes from mpsc channel to proxy
    handle.spawn(
        proxy_sink
            .sink_map_err(|_| ())
            .send_all(proxy_rx)
            .then(move |_| Ok(())),
    );

    // Handle commands incoming from proxy
    handle.spawn(
        proxy_stream
            .map_err(|_| ())
            .for_each(move |data| {
                let rpc: Rpc = unwrap!(deserialise(&*data));
                unwrap!(client_tx2.unbounded_send(Msg::Incoming(rpc)));
                Ok(())
            }).then(move |_| {
                info!("Disconnected from the proxy");
                unwrap!(client_tx3.unbounded_send(Msg::Terminate));
                Ok(())
            }),
    );

    // Probe NAT type
    unwrap!(client.probe_nat(&mut event_loop));

    // Find our connection info and wait for peer
    unwrap!(client.await_peer());

    // Handle client messages
    handle.spawn(
        client_rx
            .for_each(move |msg| {
                let res = match msg {
                    // Msg::ConnectionInfo(ci, chan) => client.set_new_conn_info(ci, chan),
                    Msg::Incoming(rpc) => client.handle_new_message(rpc),
                    Msg::RetryConnect => client.await_peer(),
                    Msg::ConnectedWithPeer(peer_id, full_stats, send_stats) => {
                        client.report_connection_result(peer_id, full_stats, send_stats)
                    }
                    Msg::Terminate => process::exit(0),
                };
                if let Err(e) = res {
                    error!("{}", e);
                }
                Ok(())
            }).then(move |_| {
                info!("Stopping...");
                Ok(())
            }),
    );

    unwrap!(event_loop.run(empty::<(), ()>()));
}
