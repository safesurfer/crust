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
extern crate hex_fmt;
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
use hex_fmt::HexFmt;
use maidsafe_utilities::{
    event_sender::{EventSender, MaidSafeEventCategory, MaidSafeObserver},
    log as logger,
    serialisation::{deserialise, serialise, SerialisationError},
    thread,
};
use mio::Poll;
use p2p::{
    Config, Handle as P2pHandle, HolePunchInfo, HolePunchMediator, Interface, NatError, NatInfo,
    NatMsg, NatType as P2pNatType, RendezvousInfo, TcpHolePunchInfo, UdpHolePunchInfo,
};
use rust_sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::io::{self, BufRead, Write};
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread::sleep;
use std::time::Duration;

pub type PublicEncryptKey = box_::PublicKey;
pub type ConnId = u32;

const RETRY_DELAY: u64 = 10;
const GIT_COMMIT: &str = include_str!(concat!(env!("OUT_DIR"), "/git_commit_hash"));

#[derive(Debug)]
pub enum Error {
    PeerNotFound,
    ConnectionNotFound,
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

enum Msg {
    RetryConnect,
    HolePunchResult(ConnId, Result<HolePunchStats, ()>),
    RendezvousInfoPrepared(NatInfo, Result<(P2pHandle, RendezvousInfo), NatError>, u32),
    DisconnectPeer(Id),
}

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Msg::RetryConnect => write!(f, "RetryConnect"),
            Msg::HolePunchResult(ref key, ref res) => {
                write!(f, "HolePunchResult({}, {:?})", key, res)
            }
            Msg::RendezvousInfoPrepared(nat_info, _res, res_token) => write!(
                f,
                "RendezvousInfoPrepared({:?}, ..., {})",
                nat_info, res_token
            ),
            Msg::DisconnectPeer(peer) => write!(f, "DisconnectPeer({:?})", peer),
        }
    }
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
struct HolePunchStats {
    tcp: Option<(ConnAddr, TcpNatTraversalResult)>,
    udp: Option<(ConnAddr, UdpNatTraversalResult)>,
}

/// Represents the current state of collected connection results.
/// Once becomes `Both`, we send the log update to the proxy.
enum ConnResults {
    Empty,
    HolePunch(Result<HolePunchStats, ()>),
    Direct(bool),
}

struct PeerConnInfo {
    our_direct_ci: Option<PrivConnectionInfo<Id>>,
    our_rendezvous_info: Option<RendezvousInfo>,
    their_direct_ci: Option<PubConnectionInfo<Id>>,
    their_rendezvous_info: Option<RendezvousInfo>,
    their_id: Option<PublicEncryptKey>,
    handle: Option<P2pHandle>,
}

enum PeerState {
    /// Gathering conn info
    ConnectionInfo {
        is_requester: bool,
        ci: PeerConnInfo,
    },
    /// Attempting to connect
    Connecting {
        is_requester: bool,
        their_id: PublicEncryptKey,
        res: ConnResults,
    },
}

struct Client {
    proxy_id: Id,
    client_tx: EventSender<MaidSafeEventCategory, Msg>,
    service: Rc<RefCell<Service<Id>>>,
    successful_conns: Vec<PublicEncryptKey>,
    attempted_conns: Vec<PublicEncryptKey>,
    failed_conns: Vec<PublicEncryptKey>,
    our_id: PublicEncryptKey,
    our_nat_info: NatInfo,
    name: Option<String>,
    id_to_conn_map: HashMap<PublicEncryptKey, ConnId>,
    peer_states: HashMap<ConnId, PeerState>,
    peer_names: HashMap<PublicEncryptKey, String>,
    p2p_el: El,
    display_available_peers: bool,
    /// A Vec of UdpHolePuncher::starting_ttl
    udp_hole_punchers: Vec<u8>,
    conn_id: u32,
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
            peer_states: Default::default(),
            peer_names: Default::default(),
            id_to_conn_map: Default::default(),
            service: Rc::new(RefCell::new(service)),
            successful_conns: Vec::new(),
            attempted_conns: Vec::new(),
            failed_conns: Vec::new(),
            our_nat_info: Default::default(),
            p2p_el,
            display_available_peers: true,
            udp_hole_punchers,
            conn_id: 0,
        }
    }

    fn set_rendezvous_info(
        &mut self,
        conn_id: ConnId,
        conn_info: Result<(P2pHandle, RendezvousInfo), NatError>,
        nat_info: NatInfo,
    ) -> Result<(), Error> {
        let (handle, conn_info) = match (nat_info, conn_info) {
            (nat_info, Ok(res)) => {
                if !is_nat_type_match(
                    &nat_info.nat_type_for_tcp,
                    &self.our_nat_info.nat_type_for_tcp,
                ) || !is_nat_type_match(
                    &nat_info.nat_type_for_udp,
                    &self.our_nat_info.nat_type_for_udp,
                ) {
                    warn!("Changed NAT type: {:?}", nat_info);
                    self.our_nat_info = nat_info;
                }
                res
            }
            (_, Err(e)) => {
                error!("Failed to get our connection info: {}", e);
                panic!("Aborting due to the previous error");
            }
        };

        let (should_connect, is_requester) = {
            let peer_state = self
                .peer_states
                .get_mut(&conn_id)
                .ok_or(Error::PeerNotFound)?;

            if let PeerState::ConnectionInfo {
                is_requester,
                ref mut ci,
            } = peer_state
            {
                (*ci).handle = Some(handle);
                (*ci).our_rendezvous_info = Some(conn_info);

                (ci.our_direct_ci.is_some(), *is_requester)
            } else {
                unreachable!("Invalid peer state");
            }
        };

        if should_connect {
            self.start_connect(conn_id, is_requester)?;
        }

        Ok(())
    }

    fn start_connect(&mut self, conn_id: ConnId, is_requester: bool) -> Result<(), Error> {
        if !is_requester {
            self.connect(conn_id)?;
        } else {
            let rpc = {
                let peer_state = self.peer_states.get(&conn_id).ok_or(Error::PeerNotFound)?;

                if let PeerState::ConnectionInfo { ci, .. } = peer_state {
                    Rpc::GetPeerReq(
                        self.name.clone(),
                        self.our_id,
                        unwrap!(ci.our_rendezvous_info.clone()),
                        unwrap!(
                            ci.our_direct_ci
                                .as_ref()
                                .map(|c| c.to_pub_connection_info())
                        ),
                    )
                } else {
                    unreachable!("Invalid peer state");
                }
            };

            self.send_rpc(&rpc)?;
        }

        Ok(())
    }

    fn set_direct_conn_info(&mut self, conn_info: ConnectionInfoResult<Id>) -> Result<(), Error> {
        let conn_id = conn_info.result_token;

        let (should_connect, is_requester) = {
            let peer_state = self
                .peer_states
                .get_mut(&conn_id)
                .ok_or(Error::PeerNotFound)?;

            if let PeerState::ConnectionInfo {
                is_requester,
                ref mut ci,
            } = peer_state
            {
                (*ci).our_direct_ci = Some(conn_info.result?);

                (ci.our_rendezvous_info.is_some(), *is_requester)
            } else {
                unreachable!("Invalid peer state");
            }
        };

        if should_connect {
            self.start_connect(conn_id, is_requester)?;
        }

        Ok(())
    }

    fn connect(&mut self, conn_id: ConnId) -> Result<(), Error> {
        let (mut peer, is_requester) = {
            let peer_state = self
                .peer_states
                .get_mut(&conn_id)
                .and_then(|peer| {
                    let (is_requester, their_id) =
                        if let PeerState::ConnectionInfo { is_requester, ci } = peer {
                            (*is_requester, ci.their_id.clone())
                        } else {
                            unreachable!("Invalid peer state");
                        };
                    Some(mem::replace(
                        peer,
                        PeerState::Connecting {
                            is_requester,
                            their_id: unwrap!(their_id),
                            res: ConnResults::Empty,
                        },
                    ))
                }).ok_or(Error::PeerNotFound)?;

            if let PeerState::ConnectionInfo { ci, is_requester } = peer_state {
                (ci, is_requester)
            } else {
                unreachable!("Invalid peer state");
            }
        };

        let udp_hp = self.udp_hole_punchers.clone();
        let client_tx = self.client_tx.clone();

        let handle = unwrap!(peer.handle.take());
        let our_p2p_ci = unwrap!(peer.our_rendezvous_info.take());
        let our_direct_ci = unwrap!(peer.our_direct_ci.take());
        let our_pub_direct_ci = our_direct_ci.to_pub_connection_info();
        let their_direct_ci = unwrap!(peer.their_direct_ci.take());
        let their_rendezvous_info = unwrap!(peer.their_rendezvous_info.take());

        // Attempt a direct connection
        self.id_to_conn_map
            .insert(unwrap!(peer.their_id.take()), conn_id);
        self.service
            .borrow()
            .connect(our_direct_ci, their_direct_ci)?;

        // Attempt hole punching
        if !is_requester {
            let our_p2p_ci2 = our_p2p_ci.clone();

            handle.fire_hole_punch(
                their_rendezvous_info,
                Box::new(move |_, _, res| {
                    // Hole punch result
                    let hole_punch_stats = collect_hole_punch_result(&our_p2p_ci2, res, &udp_hp);
                    unwrap!(client_tx.send(Msg::HolePunchResult(conn_id, hole_punch_stats)));
                }),
            );

            self.send_rpc(&Rpc::GetPeerResp(
                self.name.clone(),
                Some((self.our_id, our_p2p_ci, our_pub_direct_ci)),
            ))?;
        } else {
            // Attempt hole punching
            handle.fire_hole_punch(
                their_rendezvous_info,
                Box::new(move |_, _, res| {
                    // Hole punch result
                    let hole_punch_stats = collect_hole_punch_result(&our_p2p_ci, res, &udp_hp);
                    unwrap!(client_tx.send(Msg::HolePunchResult(conn_id, hole_punch_stats)));
                    unwrap!(client_tx.send(Msg::RetryConnect));
                }),
            );
        }

        Ok(())
    }

    fn parse_hole_punch_result(
        &mut self,
        conn_id: ConnId,
        hole_punch_stats: Result<HolePunchStats, ()>,
    ) -> Result<(), Error> {
        // Update the peer state
        let (old_state, is_requester, their_id) = {
            let peer_state = self
                .peer_states
                .get_mut(&conn_id)
                .ok_or(Error::PeerNotFound)?;

            if let PeerState::Connecting {
                ref mut res,
                is_requester,
                their_id,
            } = peer_state
            {
                let old_state = mem::replace(res, ConnResults::Empty);
                (old_state, *is_requester, *their_id)
            } else {
                unreachable!("Invalid peer state");
            }
        };

        match old_state {
            ConnResults::Empty => {
                let mut peer_state = self
                    .peer_states
                    .get_mut(&conn_id)
                    .ok_or(Error::PeerNotFound)?;

                if let PeerState::Connecting { ref mut res, .. } = peer_state {
                    *res = ConnResults::HolePunch(hole_punch_stats);
                }
            }
            ConnResults::Direct(direct_conn_res) => {
                self.report_connection_result(
                    their_id,
                    hole_punch_stats,
                    direct_conn_res,
                    is_requester,
                )?;
            }
            ConnResults::HolePunch(..) => {
                unreachable!("Invalid state");
            }
        };

        Ok(())
    }

    fn disconnect_peer(&self, peer_id: &Id) -> Result<(), Error> {
        self.service.borrow().disconnect(peer_id);
        Ok(())
    }

    fn parse_direct_conn_result(&mut self, peer_id: &Id, is_successful: bool) -> Result<(), Error> {
        let conn_id = self
            .id_to_conn_map
            .remove(&peer_id.0)
            .ok_or(Error::ConnectionNotFound)?;

        // let our_ip = self.direct_ip;
        // let their_ip = self.service.borrow().get_peer_ip_addr(peer_id);

        if is_successful {
            let client_tx = self.client_tx.clone();
            let peer_id = peer_id.clone();

            thread::named("DirectConnDrop", move || {
                sleep(Duration::from_secs(5));
                unwrap!(client_tx.send(Msg::DisconnectPeer(peer_id)));
            }).detach();
        }

        // Update the peer state
        let (old_state, is_requester, their_id) = {
            let peer_state = self
                .peer_states
                .get_mut(&conn_id)
                .ok_or(Error::PeerNotFound)?;

            if let PeerState::Connecting {
                ref mut res,
                is_requester,
                their_id,
            } = peer_state
            {
                let old_state = mem::replace(res, ConnResults::Empty);
                (old_state, *is_requester, *their_id)
            } else {
                unreachable!("Invalid peer state");
            }
        };

        match old_state {
            ConnResults::Empty => {
                if let PeerState::Connecting { ref mut res, .. } = self
                    .peer_states
                    .get_mut(&conn_id)
                    .ok_or(Error::PeerNotFound)?
                {
                    *res = ConnResults::Direct(is_successful);
                } else {
                    unreachable!("Invalid peer state");
                }
            }
            ConnResults::HolePunch(hp_res) => {
                self.report_connection_result(their_id, hp_res, is_successful, is_requester)?;
            }
            ConnResults::Direct(..) => {
                unreachable!("Invalid state");
            }
        }

        Ok(())
    }

    fn report_connection_result(
        &mut self,
        peer_id: PublicEncryptKey,
        hole_punch_result: Result<HolePunchStats, ()>,
        is_direct_successful: bool,
        send_stats: bool,
    ) -> Result<(), Error> {
        self.display_available_peers = true;

        let is_hole_punch_successful = hole_punch_result.is_ok();
        let is_successful = is_hole_punch_successful || is_direct_successful;

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
                "Successfully connected"
            } else {
                "Failed to connect"
            },
            self.get_peer_name(peer_id),
        ));

        if let Ok(HolePunchStats { ref tcp, .. }) = hole_punch_result {
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
        if let Ok(HolePunchStats { ref udp, .. }) = hole_punch_result {
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
            "Direct connection result: {}\n",
            if is_direct_successful {
                format!("local (us) <-> local (them)")
            } else {
                "Failed".to_owned()
            }
        ));

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
            let log_upd = self.aggregate_stats(peer_id, hole_punch_result, is_direct_successful);
            trace!("Sending stats");
            trace!("{:?}", log_upd);
            self.send_rpc(&Rpc::UploadLog(log_upd))?;
        }

        Ok(())
    }

    /// Probes NAT and detects the user's OS.
    fn collect_details(&mut self, upnp_support: bool) -> Result<(), Error> {
        info!("Detecting NAT type...");

        // let (nat_info, rendezvous_res) = match get_rendezvous_info(&self.p2p_el) {
        //     (nat_info, Ok(_)) => (nat_info, Ok(())),
        //     (nat_info, Err(e)) => (nat_info, Err(e)),
        // };

        // let nat_type_tcp = nat_info.nat_type_for_tcp.clone();
        // let nat_type_udp = nat_info.nat_type_for_udp.clone();

        let nat_type_tcp = P2pNatType::EIM;
        let nat_type_udp = P2pNatType::EIM;

        info!("Detected NAT type for TCP {:?}", nat_type_tcp);
        info!("Detected NAT type for UDP {:?}", nat_type_udp);

        let os_type = detect_os();
        info!("Detected OS type: {:?}", os_type);

        info!(
            "{}",
            if upnp_support {
                "UPnP is supported"
            } else {
                "UPnP is not supported"
            }
        );

        // self.our_nat_info = nat_info;

        // Send the NAT type to the bootstrap proxy
        self.send_rpc(&Rpc::UpdateDetails(PeerDetails {
            name: self.name.clone(),
            nat_type_udp,
            nat_type_tcp,
            os: os_type,
            upnp: upnp_support,
            version: GIT_COMMIT.to_owned(),
        }))?;

        // if let Err(err) = rendezvous_res {
        //     rendezvous_error(err);
        // }

        Ok(())
    }

    fn aggregate_stats(
        &self,
        peer: PublicEncryptKey,
        hole_punch_result: Result<HolePunchStats, ()>,
        is_direct_successful: bool,
    ) -> LogUpdate {
        let mut tcp_hole_punch_result = TcpNatTraversalResult::Failed;
        let mut udp_hole_punch_result = UdpNatTraversalResult::Failed;

        if let Ok(res) = hole_punch_result {
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
            is_direct_successful,
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

    /// Collects both rendezvous + Crust direct connection info
    fn initiate_connection(
        &mut self,
        their_id: Option<PublicEncryptKey>,
        their_rendezvous_info: Option<RendezvousInfo>,
        their_direct_ci: Option<PubConnectionInfo<Id>>,
        is_requester: bool,
    ) -> ConnId {
        let res_token = self.conn_id;

        self.service.borrow().prepare_connection_info(res_token);
        get_rendezvous_info(&self.p2p_el, self.client_tx.clone(), res_token);

        self.peer_states.insert(
            self.conn_id,
            PeerState::ConnectionInfo {
                is_requester,
                ci: PeerConnInfo {
                    our_direct_ci: None,
                    our_rendezvous_info: None,
                    handle: None,
                    their_id,
                    their_rendezvous_info,
                    their_direct_ci,
                },
            },
        );

        self.conn_id += 1;

        res_token
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
                if let Some((their_id, rendezvous_info, direct_ci)) = ci_opt {
                    // Attempt to connect with peer
                    self.attempted_conns.push(their_id);
                    if let Some(name) = name {
                        self.peer_names.insert(their_id, name.clone());
                    }
                    info!(
                        "Attempting to connect with {}...",
                        self.get_peer_name(their_id)
                    );

                    let conn_id = *self
                        .id_to_conn_map
                        .get(&self.our_id)
                        .ok_or(Error::ConnectionNotFound)?;

                    {
                        let mut ci = self
                            .peer_states
                            .get_mut(&conn_id)
                            .ok_or(Error::PeerNotFound)?;
                        if let PeerState::ConnectionInfo { ref mut ci, .. } = ci {
                            (*ci).their_rendezvous_info = Some(rendezvous_info);
                            (*ci).their_direct_ci = Some(direct_ci);
                            (*ci).their_id = Some(their_id);
                        } else {
                            unreachable!("Invalid peer state");
                        }
                    }

                    self.connect(conn_id)?;
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
            Rpc::GetPeerReq(name, their_id, their_rendezvous_ci, their_direct_ci) => {
                // Someone requested a direct connection with us
                if let Some(name) = name {
                    self.peer_names.insert(their_id, name.clone());
                }
                self.attempted_conns.push(their_id);

                info!(
                    "Attempting to connect with {}...",
                    self.get_peer_name(their_id)
                );

                self.initiate_connection(
                    Some(their_id),
                    Some(their_rendezvous_ci),
                    Some(their_direct_ci),
                    false,
                );
            }
            _ => {
                error!("Invalid command from the proxy");
            }
        }

        Ok(())
    }

    fn await_peer(&mut self) -> Result<(), Error> {
        let conn_id = self.initiate_connection(None, None, None, true);
        self.id_to_conn_map.insert(self.our_id.clone(), conn_id);

        Ok(())
    }
}

fn is_nat_type_match(a: &P2pNatType, b: &P2pNatType) -> bool {
    match (a, b) {
        (P2pNatType::EDM(_), P2pNatType::EDM(_))
        | (P2pNatType::EDMRandomIp(_), P2pNatType::EDMRandomIp(_))
        | (P2pNatType::EDMRandomPort(_), P2pNatType::EDMRandomPort(_))
        | (P2pNatType::EIM, P2pNatType::EIM) => true,
        (_, _) => false,
    }
}

fn rendezvous_error(error: NatError) -> ! {
    error!(
        "\n\nFailed to collect our connection information. Error description: {}\nPlease try again later and if the error persists please contact us and send the log file.\n\nPress Enter to continue...",
        error
    );

    let stdin = io::stdin();
    let mut readline = String::new();
    unwrap!(stdin.lock().read_line(&mut readline));

    std::process::exit(-1);
}

fn collect_hole_punch_result(
    our_p2p_ci: &RendezvousInfo,
    conn_res: Result<HolePunchInfo, NatError>,
    udp_hole_punchers: &Vec<u8>,
) -> Result<HolePunchStats, ()> {
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
                    our: unwrap!(our_p2p_ci.tcp),
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
            let our_external_addr = our_p2p_ci.udp.get(hole_puncher_idx);

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

    Ok(HolePunchStats { tcp, udp })
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

fn get_rendezvous_info(el: &El, tx: EventSender<MaidSafeEventCategory, Msg>, res_token: u32) {
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let get_info = move |_: &mut Interface, _: &Poll, nat_info, res| {
            unwrap!(tx.send(Msg::RendezvousInfoPrepared(nat_info, res, res_token)));
        };
        unwrap!(HolePunchMediator::start(ifc, poll, Box::new(get_info)));
    })));
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

    unwrap!(svc.start_listening_tcp());

    if let MaidSafeEventCategory::Crust = unwrap!(category_rx.recv()) {
    } else {
        unreachable!("Unexpected category");
    };
    let igd_status = if let Event::ListenerStarted(_port, igd_status) = unwrap!(crust_rx.recv()) {
        (igd_status)
    } else {
        panic!("Could not start TCP listeners");
    };

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
    unwrap!(client.collect_details(igd_status));

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
                        Msg::HolePunchResult(conn_id, hole_punch_stats) => {
                            client.parse_hole_punch_result(conn_id, hole_punch_stats)
                        }
                        Msg::RendezvousInfoPrepared(nat_type, rendezvous_info, res_token) => {
                            client.set_rendezvous_info(res_token, rendezvous_info, nat_type)
                        }
                        Msg::DisconnectPeer(peer_id) => client.disconnect_peer(&peer_id),
                    };
                    if let Err(e) = res {
                        error!("{}", e);
                    }
                }
            },
            Ok(MaidSafeEventCategory::Crust) => match crust_rx.try_recv() {
                Ok(Event::ConnectionInfoPrepared(conn_info)) => {
                    unwrap!(client.set_direct_conn_info(conn_info));
                }
                Ok(Event::ConnectSuccess(peer_id)) => {
                    unwrap!(client.parse_direct_conn_result(&peer_id, true));
                }
                Ok(Event::ConnectFailure(peer_id)) => {
                    unwrap!(client.parse_direct_conn_result(&peer_id, false));
                }
                Ok(Event::NewMessage(peer_id, _user, data)) => {
                    if peer_id != proxy_id {
                        warn!("Unknown peer: {:<8}", HexFmt(peer_id.0));
                        continue;
                    }
                    let rpc: Rpc = unwrap!(deserialise(&data));
                    unwrap!(client.handle_new_message(rpc));
                }
                Ok(Event::LostPeer(peer_id)) => {
                    if peer_id == proxy_id {
                        info!("Disconnected from the proxy");
                        break;
                    }
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
