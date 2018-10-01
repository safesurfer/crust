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

extern crate bytes;
extern crate clap;
extern crate crust;
extern crate future_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate p2p;
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
use common::{LogUpdate, NatTraversalResult, Os, Rpc};
use crust::{
    ConfigFile, ConnectionResult, CrustError, CrustUser, PaAddr, PubConnectionInfo, Service,
    SingleConnectionError,
};
use future_utils::bi_channel::{self, UnboundedBiChannel};
use future_utils::mpsc::SendError;
use futures::sync::mpsc::{self, UnboundedSender};
use futures::{future::empty, Future, Sink, Stream};
use maidsafe_utilities::{
    log as logger,
    serialisation::{deserialise, serialise, SerialisationError},
};
use safe_crypto::PublicEncryptKey;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Write};
use std::process;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio_core::reactor::{Core, Handle};
use tokio_timer::Delay;

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
    ConnectionInfo(PubConnectionInfo, UnboundedBiChannel<PubConnectionInfo>),
    Incoming(Rpc),
    Stats(LogUpdate),
    RetryConnect,
    Terminate,
    ConnectedWithPeer(Option<PublicEncryptKey>, Vec<ConnectionResult>, bool),
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

struct Client {
    handle: Handle,
    proxy_tx: UnboundedSender<Bytes>,
    client_tx: UnboundedSender<Msg>,
    ci_channel: Option<UnboundedBiChannel<PubConnectionInfo>>,
    our_ci: Option<PubConnectionInfo>,
    service: Rc<RefCell<Service>>,
    successful_conns: Vec<PublicEncryptKey>,
    attempted_conns: Vec<PublicEncryptKey>,
    failed_conns: Vec<PublicEncryptKey>,
    connecting_to: Option<PublicEncryptKey>,
    name: Option<String>,
    peer_names: HashMap<PublicEncryptKey, String>,
}

impl Client {
    fn new(
        name: Option<String>,
        service: Service,
        handle: Handle,
        proxy_tx: UnboundedSender<Bytes>,
        client_tx: UnboundedSender<Msg>,
    ) -> Self {
        Client {
            handle,
            proxy_tx,
            client_tx,
            name,
            peer_names: Default::default(),
            service: Rc::new(RefCell::new(service)),
            ci_channel: None,
            our_ci: None,
            successful_conns: Vec::new(),
            attempted_conns: Vec::new(),
            failed_conns: Vec::new(),
            connecting_to: None,
        }
    }

    fn connected_with_peer(
        &mut self,
        peer_id: Option<PublicEncryptKey>,
        conn_res: Vec<ConnectionResult>,
        send_stats: bool,
    ) -> Result<(), Error> {
        let is_successful = conn_res.iter().fold(false, |prev, res| {
            if prev == false {
                res.result.is_ok()
            } else {
                prev
            }
        });

        let peer_id = peer_id.unwrap_or_else(|| unwrap!(self.connecting_to.take()));
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
        info!("Results: {:?}", conn_res);

        // Send stats only if the requester is us
        if send_stats {
            let log_upd = self.aggregate_stats(peer_id, conn_res);
            info!("Stats: {:?}", log_upd);
            unwrap!(self.client_tx.unbounded_send(Msg::Stats(log_upd)));
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
        conn_res: Vec<ConnectionResult>,
    ) -> LogUpdate {
        let mut is_direct_successful = false;
        let mut tcp_hole_punch_result = NatTraversalResult::Failed;
        let mut utp_hole_punch_result = NatTraversalResult::Failed;

        for res in conn_res {
            if res.is_direct {
                is_direct_successful = res.result.is_ok();
            } else {
                match (res.their_addr, res.our_addr) {
                    // TCP hole punch
                    (Some(PaAddr::Tcp(_)), Some(PaAddr::Tcp(_))) => {
                        if res.result.is_ok() {
                            tcp_hole_punch_result = NatTraversalResult::Succeeded {
                                time_spent: res.duration,
                            };
                        } else {
                            tcp_hole_punch_result = NatTraversalResult::Failed;
                        }
                    }
                    // uTP hole punch
                    (Some(PaAddr::Utp(..)), Some(PaAddr::Utp(..))) => {
                        if res.result.is_ok() {
                            utp_hole_punch_result = NatTraversalResult::Succeeded {
                                time_spent: res.duration,
                            };
                        } else {
                            utp_hole_punch_result = NatTraversalResult::Failed;
                        }
                    }
                    (_, _) => {
                        error!(
                            "Unexpected pair: ({:?}, {:?})",
                            res.their_addr, res.our_addr
                        );
                    }
                }
            }
        }

        LogUpdate {
            peer,
            is_direct_successful,
            utp_hole_punch_result,
            tcp_hole_punch_result,
        }
    }

    fn send_rpc(&self, rpc: &Rpc) -> Result<(), Error> {
        info!("Sending {}", rpc);
        let bytes = serialise(&rpc)?;
        self.proxy_tx.unbounded_send(Bytes::from(bytes))?;
        Ok(())
    }

    fn set_new_conn_info(
        &mut self,
        our_ci: PubConnectionInfo,
        ci_chan: UnboundedBiChannel<PubConnectionInfo>,
    ) -> Result<(), Error> {
        info!("Updating our connection info");

        self.our_ci = Some(our_ci.clone());
        self.ci_channel = Some(ci_chan);

        self.send_rpc(&Rpc::GetPeerReq(self.name.clone(), our_ci))
    }

    fn send_stats(&self, stats: LogUpdate) -> Result<(), Error> {
        self.send_rpc(&Rpc::UploadLog(stats))
    }

    fn get_peer_name(&self, id: PublicEncryptKey) -> String {
        if let Some(name) = self.peer_names.get(&id) {
            format!("{} ({})", name, id)
        } else {
            format!("{}", id)
        }
    }

    fn handle_new_message(&mut self, rpc_cmd: Rpc) -> Result<(), Error> {
        info!("Received {}", rpc_cmd);

        match rpc_cmd {
            Rpc::GetPeerResp(name, ci_opt) => {
                if let Some(ci) = ci_opt {
                    // Attempt to connect with peer
                    self.attempted_conns.push(ci.id());
                    if let Some(name) = name {
                        self.peer_names.insert(ci.id(), name.clone());
                    }
                    self.connecting_to = Some(ci.id());
                    info!(
                        "Attempting to connect with {}...",
                        self.get_peer_name(ci.id())
                    );
                    unwrap!(self.ci_channel.take()).unbounded_send(ci)?;
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
                let theirs_id = theirs_ci.id();
                if let Some(name) = name {
                    self.peer_names.insert(theirs_id, name.clone());
                }
                self.attempted_conns.push(theirs_id);

                info!(
                    "Attempting to connect with {}...",
                    self.get_peer_name(theirs_id)
                );

                let client_tx = self.client_tx.clone();;
                let svc = self.service.borrow();
                let (ci_chan1, ci_chan2) = bi_channel::unbounded::<PubConnectionInfo>();

                self.handle.spawn(
                    svc.connect_all(ci_chan1)
                        .collect()
                        .and_then(move |conn_res| {
                            unwrap!(client_tx.unbounded_send(Msg::ConnectedWithPeer(
                                Some(theirs_id),
                                conn_res,
                                false
                            )));
                            Ok(())
                        }).map_err(move |e| {
                            error!("{}", e);
                        }),
                );

                let proxy_tx = self.proxy_tx.clone();
                let name = self.name.clone();

                self.handle.spawn(
                    ci_chan2
                        .into_future()
                        .and_then(move |(our_ci_opt, ci_chan2)| {
                            let our_ci = unwrap!(our_ci_opt);
                            unwrap!(ci_chan2.unbounded_send(theirs_ci));

                            let rpc = Rpc::GetPeerResp(name, Some(our_ci));
                            info!("Sending {}", rpc);
                            let bytes = unwrap!(serialise(&rpc));
                            unwrap!(proxy_tx.unbounded_send(Bytes::from(bytes)));

                            Ok(())
                        }).then(move |_| Ok(())),
                );
            }
            _ => {
                error!("Invalid command from the proxy");
            }
        }

        Ok(())
    }

    fn await_peer(&self) -> Result<(), Error> {
        let (ci_chan1, ci_chan2) = bi_channel::unbounded::<PubConnectionInfo>();

        let client_tx = self.client_tx.clone();
        let client_tx2 = self.client_tx.clone();

        self.handle.spawn(
            ci_chan2
                .into_future()
                .and_then(move |(our_ci_opt, ci_chan2)| {
                    let our_ci = unwrap!(our_ci_opt);
                    unwrap!(client_tx.unbounded_send(Msg::ConnectionInfo(our_ci, ci_chan2)));
                    Ok(())
                }).then(move |_| Ok(())),
        );

        let fut = self
            .service
            .borrow()
            .connect_all(ci_chan1)
            .collect()
            .then(move |res| {
                match res {
                    Ok(conn_res) => {
                        unwrap!(
                            client_tx2.unbounded_send(Msg::ConnectedWithPeer(None, conn_res, true))
                        );
                        // Disconnect and try again with another peer
                        unwrap!(client_tx2.unbounded_send(Msg::RetryConnect));
                    }
                    Err(SingleConnectionError::DeadChannel) => {
                        // Channel was closed
                    }
                    Err(e) => {
                        error!("{}", e);
                    }
                }
                Ok(())
            });

        self.handle.spawn(fut);

        Ok(())
    }
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
        ).get_matches();

    print!("Please enter your name (or press Enter if you don't want any): ");
    unwrap!(io::stdout().flush());

    let stdin = io::stdin();
    let mut our_name = String::new();
    unwrap!(stdin.lock().read_line(&mut our_name));
    let our_name = our_name.trim().to_string();

    let config = unwrap!(if let Some(cfg_path) = matches.value_of("config") {
        info!("Loading config from {}", cfg_path);
        ConfigFile::open_path(From::from(cfg_path))
    } else {
        ConfigFile::open_default()
    });

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
        if our_name.is_empty() {
            None
        } else {
            Some(our_name)
        },
        svc,
        handle.clone(),
        proxy_tx.clone(),
        client_tx.clone(),
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
                    Msg::ConnectionInfo(ci, chan) => client.set_new_conn_info(ci, chan),
                    Msg::Incoming(rpc) => client.handle_new_message(rpc),
                    Msg::Stats(stats) => client.send_stats(stats),
                    Msg::RetryConnect => client.await_peer(),
                    Msg::ConnectedWithPeer(peer_id, peer, send_stats) => {
                        client.connected_with_peer(peer_id, peer, send_stats)
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
