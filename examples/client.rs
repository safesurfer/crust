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

extern crate config_file_handler;
extern crate crossbeam;
extern crate crust;
extern crate get_if_addrs;
extern crate hex_fmt;
extern crate igd;
extern crate mio;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate p2p;
extern crate rand;
extern crate rust_sodium;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

mod common;

use common::event_loop::{spawn_event_loop, El};
use common::{Id, LogUpdate, Os, PeerDetails, Rpc, TcpNatTraversalResult, UdpNatTraversalResult};
use crust::*;
use get_if_addrs::IfAddr;
use hex_fmt::HexFmt;
use igd::PortMappingProtocol;
use maidsafe_utilities::{
    event_sender::{EventSender, MaidSafeEventCategory, MaidSafeObserver},
    log as logger,
    serialisation::{deserialise, serialise, SerialisationError},
    thread,
};
use mio::Poll;
use p2p::{
    Config, Handle as P2pHandle, HolePunchInfo, HolePunchMediator, Interface, NatError, NatMsg,
    NatType as P2pNatType, RendezvousInfo, Res, TcpHolePunchInfo, UdpHolePunchInfo,
};
use rand::Rng;
use rust_sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;

pub type PublicEncryptKey = box_::PublicKey;

const RETRY_DELAY: u64 = 10;
const GIT_COMMIT: &str = include_str!(concat!(env!("OUT_DIR"), "/git_commit_hash"));

#[derive(Debug)]
pub enum Error {
    Crust(CrustError),
    Unexpected(String),
    Serialisation(SerialisationError),
    Io(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ::std::error::Error for Error {}

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

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}

impl From<String> for Error {
    fn from(string: String) -> Self {
        Error::Unexpected(string)
    }
}

#[derive(Debug)]
enum Msg {
    RetryConnect,
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

fn retry_connection(tx: &EventSender<MaidSafeEventCategory, Msg>) {
    let tx2 = tx.clone();

    thread::named("RetryDelay", move || {
        sleep(Duration::from_secs(RETRY_DELAY));
        unwrap!(tx2.send(Msg::RetryConnect));
    }).detach();
}

#[derive(Debug)]
struct ConnAddr {
    our: SocketAddr,
    their: SocketAddr,
}

#[derive(Debug)]
struct FullConnStats {
    tcp: Option<(ConnAddr, TcpNatTraversalResult)>,
    udp: Option<(ConnAddr, UdpNatTraversalResult)>,
}

struct Client {
    proxy_id: Id,
    client_tx: EventSender<MaidSafeEventCategory, Msg>,
    service: Rc<RefCell<Service<Id>>>,
    successful_conns: Vec<PublicEncryptKey>,
    attempted_conns: Vec<PublicEncryptKey>,
    failed_conns: Vec<PublicEncryptKey>,
    our_id: PublicEncryptKey,
    our_ci: Option<RendezvousInfo>,
    our_nat_type_udp: Option<P2pNatType>,
    our_nat_type_tcp: Option<P2pNatType>,
    p2p_handle: Option<P2pHandle>,
    name: Option<String>,
    peer_names: HashMap<PublicEncryptKey, String>,
    p2p_el: El,
    display_available_peers: bool,
    udp_hole_punchers: Vec<u8>, // a vec of UdpHolePuncher::starting_ttl
}

impl Client {
    fn new(
        our_id: PublicEncryptKey,
        proxy_id: Id,
        name: Option<String>,
        service: Service<Id>,
        client_tx: EventSender<MaidSafeEventCategory, Msg>,
        p2p_el: El,
        udp_hole_punchers: Vec<u8>,
    ) -> Self {
        Client {
            our_id,
            client_tx,
            name,
            proxy_id,
            p2p_handle: None,
            peer_names: Default::default(),
            service: Rc::new(RefCell::new(service)),
            successful_conns: Vec::new(),
            attempted_conns: Vec::new(),
            failed_conns: Vec::new(),
            our_ci: None,
            our_nat_type_tcp: None,
            our_nat_type_udp: None,
            p2p_el,
            display_available_peers: true,
            udp_hole_punchers,
        }
    }

    fn report_connection_result(
        &mut self,
        peer_id: PublicEncryptKey,
        conn_res: Result<FullConnStats, ()>,
        send_stats: bool,
    ) -> Result<(), Error> {
        self.display_available_peers = true;

        let is_successful = conn_res.is_ok();

        if is_successful {
            self.successful_conns.push(peer_id);
        } else {
            self.failed_conns.push(peer_id);
        }

        let mut log_output = String::new();

        // Connected to peer
        log_output.push_str(&format!(
            "\n===============================================\n{} with {}\n",
            if is_successful {
                "Sucessfully connected"
            } else {
                "Failed to connect"
            },
            self.get_peer_name(peer_id),
        ));

        if let Ok(FullConnStats { ref tcp, .. }) = conn_res {
            log_output.push_str(&format!(
                "TCP result: {}\n",
                if let Some((tcp, TcpNatTraversalResult::Succeeded { time_spent })) = tcp {
                    format!(
                        "{} (us) <-> {} (them), connected in {:?}",
                        tcp.our, tcp.their, time_spent
                    )
                } else {
                    "Failed".to_owned()
                }
            ));
        }
        if let Ok(FullConnStats { ref udp, .. }) = conn_res {
            log_output.push_str(&format!(
                "UDP result: {}\n",
                if let Some((udp, UdpNatTraversalResult::Succeeded { time_spent, .. })) = udp {
                    format!(
                        "{} (us) <-> {} (them), connected in {:?}",
                        udp.our, udp.their, time_spent
                    )
                } else {
                    "Failed".to_owned()
                }
            ));
        }

        log_output.push_str(&format!(
            "Successful connections: {:?}\n",
            self.successful_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        ));
        log_output.push_str(&format!(
            "Failed connections: {:?}\n",
            self.failed_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        ));
        log_output.push_str(&format!(
            "Attempted connections: {:?}\n",
            self.attempted_conns
                .iter()
                .map(|id| self.get_peer_name(*id))
                .collect::<Vec<String>>()
        ));

        log_output.push_str("===============================================");

        info!("{}", log_output);

        // Send stats only if the requester is us
        if send_stats {
            let log_upd = self.aggregate_stats(peer_id, conn_res);
            trace!("Sending stats");
            trace!("{:?}", log_upd);
            self.send_rpc(&Rpc::UploadLog(log_upd))?;
        }

        Ok(())
    }

    /// Probes NAT, detects UPnP support, and the user's OS.
    fn collect_details(&mut self) -> Result<(), Error> {
        info!("Detecting NAT type...");
        let (_handle, our_ci) = match get_rendezvous_info(&self.p2p_el) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to detect our NAT type: {}", e);
                panic!("Aborting due to the previous error");
            }
        };

        let nat_type_tcp = our_ci.nat_type_for_tcp;
        info!("Detected NAT type for TCP {:?}", nat_type_tcp);
        let nat_type_udp = our_ci.nat_type_for_udp;
        info!("Detected NAT type for UDP {:?}", nat_type_udp);

        let os_type = detect_os();
        info!("Detected OS type: {:?}", os_type);

        let upnp_support = detect_upnp()?;
        info!(
            "{}",
            if upnp_support {
                "UPnP is supported"
            } else {
                "UPnP is not supported"
            }
        );

        self.our_nat_type_tcp = Some(nat_type_tcp.clone());
        self.our_nat_type_udp = Some(nat_type_udp.clone());

        // Send the NAT type to the bootstrap proxy
        self.send_rpc(&Rpc::UpdateDetails(PeerDetails {
            name: self.name.clone(),
            nat_type_udp,
            nat_type_tcp,
            os: os_type,
            upnp: upnp_support,
            version: GIT_COMMIT.to_owned(),
        }))
    }

    fn aggregate_stats(
        &self,
        peer: PublicEncryptKey,
        conn_res: Result<FullConnStats, ()>,
    ) -> LogUpdate {
        let mut tcp_hole_punch_result = TcpNatTraversalResult::Failed;
        let mut udp_hole_punch_result = UdpNatTraversalResult::Failed;

        if let Ok(res) = conn_res {
            if let Some((_, tcp_traversal_result)) = res.tcp {
                tcp_hole_punch_result = tcp_traversal_result;
            }
            if let Some((_, udp_traversal_result)) = res.udp {
                udp_hole_punch_result = udp_traversal_result;
            }
        }

        LogUpdate {
            peer,
            udp_hole_punch_result,
            tcp_hole_punch_result,
        }
    }

    fn send_rpc(&self, rpc: &Rpc) -> Result<(), Error> {
        trace!("Sending {}", rpc);
        let bytes = serialise(&rpc)?;
        self.service.borrow().send(&self.proxy_id, bytes, 0)?;
        Ok(())
    }

    fn get_peer_name(&self, id: PublicEncryptKey) -> String {
        if let Some(name) = self.peer_names.get(&id) {
            format!("{} ({:<8})", name, HexFmt(id))
        } else {
            format!("{:<8}", HexFmt(id))
        }
    }

    fn handle_new_message(&mut self, rpc_cmd: Rpc) -> Result<(), Error> {
        trace!("Received {}", rpc_cmd);

        match rpc_cmd {
            Rpc::WrongVersion(expected_version) => {
                info!(
                    "\n\nYou're using an outdated version of the client (you are using version {}, but the latest version is {}).\nPlease download the latest available version from https://github.com/maidsafe/crust/releases and restart the client.\n",
                    &GIT_COMMIT[0..6],
                    &expected_version[0..6]
                );
            }
            Rpc::GetPeerResp(name, ci_opt) => {
                if let Some((their_id, ci)) = ci_opt {
                    // Attempt to connect with peer
                    self.attempted_conns.push(their_id);
                    if let Some(name) = name {
                        self.peer_names.insert(their_id, name.clone());
                    }
                    info!(
                        "Attempting to connect with {}...",
                        self.get_peer_name(their_id)
                    );

                    let client_tx = self.client_tx.clone();
                    let our_ci = unwrap!(self.our_ci.take());
                    let udp_hp = self.udp_hole_punchers.clone();

                    unwrap!(self.p2p_handle.take()).fire_hole_punch(
                        ci,
                        Box::new(move |_, _, res| {
                            // Hole punch result
                            let full_stats = collect_conn_result(&our_ci, res, &udp_hp);
                            unwrap!(
                                client_tx.send(Msg::ConnectedWithPeer(their_id, full_stats, true))
                            );
                            unwrap!(client_tx.send(Msg::RetryConnect));
                        }),
                    );
                } else {
                    // Retry again in some time
                    if self.display_available_peers {
                        info!(
                            "\n\nAll available peers have been attempted to be reached. Checking for new peers every {} seconds.",
                            RETRY_DELAY
                        );
                        self.display_available_peers = false;
                    }

                    retry_connection(&self.client_tx);
                }
            }
            Rpc::GetPeerReq(name, their_id, their_ci) => {
                // Someone requested a direct connection with us
                if let Some(name) = name {
                    self.peer_names.insert(their_id, name.clone());
                }
                self.attempted_conns.push(their_id);

                info!(
                    "Attempting to connect with {}...",
                    self.get_peer_name(their_id)
                );

                let client_tx = self.client_tx.clone();;
                let name = self.name.clone();

                let (handle, mut our_ci) = match get_rendezvous_info(&self.p2p_el) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to get our connection info: {}", e);
                        panic!("Aborting due to the previous error");
                    }
                };
                trace!("Our responder CI: {:?}", our_ci);

                let our_ci2 = our_ci.clone();
                let udp_hp = self.udp_hole_punchers.clone();

                handle.fire_hole_punch(
                    their_ci,
                    Box::new(move |_, _, res| {
                        // Hole punch result
                        let full_stats = collect_conn_result(&our_ci2, res, &udp_hp);
                        unwrap!(
                            client_tx.send(Msg::ConnectedWithPeer(their_id, full_stats, false))
                        );
                    }),
                );

                self.send_rpc(&Rpc::GetPeerResp(name, Some((self.our_id, our_ci))))?;
            }
            _ => {
                error!("Invalid command from the proxy");
            }
        }

        Ok(())
    }

    fn await_peer(&mut self) -> Result<(), Error> {
        let (handle, our_ci) = match get_rendezvous_info(&self.p2p_el) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to get our connection info: {}", e);
                panic!("Aborting due to the previous error");
            }
        };
        trace!("Our requester CI: {:?}", our_ci);

        self.p2p_handle = Some(handle);
        self.our_ci = Some(our_ci.clone());

        self.send_rpc(&Rpc::GetPeerReq(self.name.clone(), self.our_id, our_ci))?;

        Ok(())
    }
}

fn collect_conn_result(
    our_ci: &RendezvousInfo,
    conn_res: Result<HolePunchInfo, NatError>,
    udp_hole_punchers: &Vec<u8>,
) -> Result<FullConnStats, ()> {
    let HolePunchInfo { tcp, udp, .. } = match conn_res {
        Ok(conn_info) => conn_info,
        Err(_e) => {
            // could not traverse nat type
            return Err(());
        }
    };

    let tcp = if let Some(TcpHolePunchInfo { sock, dur, .. }) = tcp {
        let peer_addr = match sock.peer_addr() {
            Ok(pa) => Some(pa),
            Err(e) => {
                debug!("Failed to get TCP peer address: {}", e);
                None
            }
        };
        if let Some(peer_addr) = peer_addr {
            thread::named("TCPConnDrop", move || {
                sleep(Duration::from_secs(5));
                drop(sock);
            }).detach();

            Some((
                ConnAddr {
                    our: unwrap!(our_ci.tcp),
                    their: peer_addr,
                },
                TcpNatTraversalResult::Succeeded { time_spent: dur },
            ))
        } else {
            None
        }
    } else {
        None
    };

    let udp = if let Some(UdpHolePunchInfo {
        sock,
        peer,
        starting_ttl,
        ttl_on_being_reached,
        dur,
        ..
    }) = udp
    {
        thread::named("UDSockDrop", move || {
            sleep(Duration::from_secs(5));
            drop(sock);
        }).detach();

        // Derive our ext addr given the starting TTL
        if let Some((hole_puncher_idx, _hole_puncher)) = udp_hole_punchers
            .iter()
            .enumerate()
            .find(|(_, puncher_starting_ttl)| **puncher_starting_ttl == starting_ttl as u8)
        {
            let our_external_addr = our_ci.udp.get(hole_puncher_idx);

            if let Some(our) = our_external_addr {
                Some((
                    ConnAddr {
                        our: our.clone(),
                        their: peer,
                    },
                    UdpNatTraversalResult::Succeeded {
                        time_spent: dur,
                        starting_ttl,
                        ttl_on_being_reached,
                    },
                ))
            } else {
                debug!(
                    "P2P didn't provide our IP address in RendezvousInfo. hole_puncher_idx: {}",
                    hole_puncher_idx
                );
                None
            }
        } else {
            debug!(
                "Unexpected starting_ttl passed from p2p: {}, no hole puncher found",
                starting_ttl
            );
            None
        }
    } else {
        None
    };

    Ok(FullConnStats { tcp, udp })
}

fn get_user_name() -> Option<String> {
    print!("Please enter your name (or press Enter to keep it blank): ");
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

fn detect_upnp() -> Result<bool, Error> {
    // Detect our interfaces
    info!("Detecting UPnP support...");

    let ifs = get_if_addrs::get_if_addrs()?;
    let mut ifv4s = Vec::with_capacity(5);
    for interface in ifs {
        match interface.addr {
            IfAddr::V4(v4_addr) => ifv4s.push((v4_addr.ip, None)),
            _ => (),
        }
    }

    crossbeam::scope(|scope| {
        let mut guards = Vec::with_capacity(ifv4s.len());

        for ifv4 in &mut ifv4s {
            if !ifv4.0.is_loopback() {
                guards.push(scope.spawn(move || {
                    debug!("Searching gateway {:?}", ifv4.0);
                    ifv4.1 = igd::search_gateway_from_timeout(ifv4.0, Duration::from_secs(1)).ok();
                }));
            }
        }
    });

    let port = rand::thread_rng().gen_range(10000, std::u16::MAX);

    // Ask IGD
    let (tx, rx) = mpsc::channel();
    let igd_children = {
        let mut igd_children = vec![];
        debug!("Interfaces: {:?}", ifv4s);

        for (ref ip, ref gateway) in ifv4s {
            let gateway = match *gateway {
                Some(ref gateway) => gateway.clone(),
                None => continue,
            };

            let addr_igd = SocketAddrV4::new(*ip, port);
            let tx2 = tx.clone();

            igd_children.push(thread::named("IGD-Address-Mapping", move || {
                debug!("Getting any address for {:?}", addr_igd);
                let res =
                    gateway.get_any_address(PortMappingProtocol::TCP, addr_igd, 10, "MaidSafeNat");
                let ext_addr = match res {
                    Ok(ext_addr) => Some(ext_addr),
                    Err(e) => {
                        debug!("IGD error: {}", e);
                        None
                    }
                };
                unwrap!(tx2.send(ext_addr));
            }));
        }

        igd_children.len()
    };

    drop(tx);

    if igd_children > 0 {
        debug!("Waiting for {} IGD scanners", igd_children);
        while let Ok(ext_addr) = rx.recv() {
            if let Some(_) = ext_addr {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn get_rendezvous_info(el: &El) -> Res<(p2p::Handle, RendezvousInfo)> {
    let (tx, rx) = mpsc::channel();
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

    let config = unwrap!(read_config_file());

    // Init P2P config and spawn the event loop
    let current_bin_dir = unwrap!(config_file_handler::current_bin_dir());

    let mut file = unwrap!(File::open(format!(
        "{}/p2p-config",
        unwrap!(current_bin_dir.as_path().to_str())
    )));
    let mut content = String::new();
    unwrap!(file.read_to_string(&mut content));
    let p2p_config: Config = unwrap!(serde_json::from_str(&content));
    let udp_hole_punchers = p2p_config
        .udp_hole_punchers
        .iter()
        .map(|udp_hp| udp_hp.starting_ttl)
        .collect();

    let (our_pk, our_sk) = box_::gen_keypair();

    let our_name = get_user_name();
    let p2p_el = spawn_event_loop(p2p_config, our_pk.clone(), our_sk);

    // Init Crust
    let (category_tx, category_rx) = mpsc::channel();
    let (crust_tx, crust_rx) = mpsc::channel();
    let (app_msg_tx, app_msg_rx) = mpsc::channel();
    let event_tx =
        MaidSafeObserver::new(crust_tx, MaidSafeEventCategory::Crust, category_tx.clone());
    let app_tx = MaidSafeObserver::new(app_msg_tx, MaidSafeEventCategory::Routing, category_tx);

    let mut svc = unwrap!(Service::with_config(event_tx, config, Id(our_pk)));

    info!("Our public ID: {:<8}", HexFmt(our_pk));

    info!("Attempting bootstrap...");
    unwrap!(svc.start_bootstrap(Default::default(), CrustUser::Client));

    if let MaidSafeEventCategory::Crust = unwrap!(category_rx.recv()) {
    } else {
        unreachable!("Unexpected category");
    };
    let (proxy_id, proxy_addr) = if let Event::BootstrapConnect::<_>(id, addr) =
        unwrap!(crust_rx.recv())
    {
        (id, addr)
    } else {
        error!("\n\nCould not connect with the proxy.\n\nThis probably means that your IP address is not registered. Please follow this link for registration: https://crusttest.maidsafe.net/auth.html\nIf you have registered your IP address and still getting this error it could mean the proxy is down or not reachable. Please contact us and provide the log file.\n\nPress Enter to continue...");

        let stdin = io::stdin();
        let mut readline = String::new();
        unwrap!(stdin.lock().read_line(&mut readline));

        return;
    };

    info!("Connected to {:<8} ({})", HexFmt(proxy_id.0), proxy_addr);

    let mut client = Client::new(
        our_pk,
        proxy_id,
        our_name,
        svc,
        app_tx,
        p2p_el,
        udp_hole_punchers,
    );

    // Probe NAT type
    unwrap!(client.collect_details());

    // Find our connection info and wait for peer
    match client.await_peer() {
        Ok(_) => (),
        Err(Error::Crust(CrustError::PeerNotFound)) => {
            // Probably the proxy has disconnected us, wait for new messages.
            ()
        }
        Err(e) => unwrap!(Err(e)),
    }

    loop {
        match category_rx.recv() {
            Ok(MaidSafeEventCategory::Routing) => match app_msg_rx.try_recv() {
                Err(e) => {
                    warn!("{}", e);
                }
                Ok(msg) => {
                    let res = match msg {
                        Msg::RetryConnect => client.await_peer(),
                        Msg::ConnectedWithPeer(peer_id, full_stats, send_stats) => {
                            client.report_connection_result(peer_id, full_stats, send_stats)
                        }
                    };
                    if let Err(e) = res {
                        error!("{}", e);
                    }
                }
            },
            Ok(MaidSafeEventCategory::Crust) => match crust_rx.try_recv() {
                Ok(Event::NewMessage(peer_id, _user, data)) => {
                    if peer_id != proxy_id {
                        warn!("Unknown peer: {:<8}", HexFmt(peer_id.0));
                        continue;
                    }
                    let rpc: Rpc = unwrap!(deserialise(&data));
                    unwrap!(client.handle_new_message(rpc));
                }
                Ok(Event::LostPeer(_)) => {
                    info!("Disconnected from the proxy");
                    break;
                }
                Ok(event) => {
                    trace!("Unexpected event {:?}", event);
                }
                Err(e) => {
                    warn!("{}", e);
                }
            },
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
}
