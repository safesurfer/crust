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

extern crate config_file_handler;
extern crate crust;
extern crate hex_fmt;
extern crate mio;
extern crate p2p;
extern crate rust_sodium;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

mod common;

use common::{Id, NatTraversalResult, Os, PeerDetails, Rpc};
use crust::*;
use hex_fmt::HexFmt;
use maidsafe_utilities::{
    event_sender::{MaidSafeEventCategory, MaidSafeObserver},
    log as logger,
    serialisation::{deserialise, serialise},
};
use p2p::RendezvousInfo;
use rand::Rng;
use rust_sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::mpsc;

type PublicEncryptKey = box_::PublicKey;

const GIT_COMMIT: &str = include_str!(concat!(env!("OUT_DIR"), "/git_commit_hash"));

mod stats {
    use serde_json;
    use {Error, LogEntry};

    pub fn output_log(log: &LogEntry) -> Result<(), Error> {
        let json = serde_json::to_string(log)?;
        info!("{}", json);
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Crust(CrustError),
    Io(io::Error),
    Unexpected(String),
    PartialPeerInfo,
    WrongPeerPairing(PublicEncryptKey, PublicEncryptKey),
    PeerNotFound(PublicEncryptKey),
    WrongPeerVersion(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ::std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Unexpected(format!("Serialisation error: {}", err))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<mpsc::TryRecvError> for Error {
    fn from(err: mpsc::TryRecvError) -> Self {
        Error::Unexpected(format!("Recv error: {}", err))
    }
}

impl From<CrustError> for Error {
    fn from(err: CrustError) -> Self {
        Error::Crust(err)
    }
}

impl From<String> for Error {
    fn from(string: String) -> Self {
        Error::Unexpected(string)
    }
}

/// Full log entries containing all info feeded to the dashboard.
/// JSON serialise this.
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct LogEntry {
    peer_requester: common::Peer,
    peer_responder: common::Peer,
    udp_hole_punch_result: NatTraversalResult,
    tcp_hole_punch_result: NatTraversalResult,
    is_direct_successful: bool,
}

#[derive(Eq, PartialEq, Hash, Debug)]
enum PeerStatus {
    Pending,
    Matched,
}

struct ConnectedPeer {
    id: PublicEncryptKey,
    addr: IpAddr,
    p2p_conn_info: Option<RendezvousInfo>,
    direct_conn_info: Option<PubConnectionInfo<Id>>,
    details: Option<PeerDetails>,
    peers_known: HashMap<PublicEncryptKey, PeerStatus>,
}

impl ConnectedPeer {
    fn new(id: PublicEncryptKey, addr: IpAddr) -> Self {
        ConnectedPeer {
            id,
            addr,
            details: None,
            peers_known: HashMap::default(),
            p2p_conn_info: None,
            direct_conn_info: None,
        }
    }

    fn get_details<R, F>(&self, details_map: F) -> Result<R, Error>
    where
        F: Fn(&PeerDetails) -> R,
    {
        self.details
            .as_ref()
            .map(details_map)
            .ok_or(Error::PartialPeerInfo)
    }
}

struct Proxy {
    peers: HashMap<PublicEncryptKey, ConnectedPeer>,
    service: Rc<RefCell<Service<Id>>>,
}

impl Proxy {
    fn new(service: Rc<RefCell<Service<Id>>>) -> Self {
        Proxy {
            service,
            peers: Default::default(),
        }
    }

    fn send_rpc(&self, peer: &Id, rpc: &Rpc) -> Result<(), Error> {
        let bytes = unwrap!(serialise(rpc));
        self.service.borrow().send(peer, bytes, 0)?;
        Ok(())
    }

    fn lost_peer(&mut self, peer_id: Id) -> Result<(), Error> {
        let peer_key = peer_id.0;

        info!("Disconnected peer {}", self.peer_name(&peer_key));

        let _ = self.peers.remove(&peer_key);
        let mut need_new_pair = Vec::new();

        for peer in self.peers.values_mut() {
            let status = peer.peers_known.remove(&peer_key);
            if let Some(PeerStatus::Pending) = status {
                need_new_pair.push(peer.id);
            }
        }

        // Find a new pair for a peer that was lost due to a connection
        for peer_key in need_new_pair {
            let pair = self.match_peer(peer_key);
            self.connect_with_match(None, peer_key, pair)?;
        }

        Ok(())
    }

    fn new_peer(&mut self, peer: Id) -> Result<(), Error> {
        let peer_key = peer.0;

        if self.peers.contains_key(&peer_key) {
            warn!(
                "Peer ID {:<8} attempted to connect once again; dropping connection",
                HexFmt(peer_key.0)
            );
            self.service.borrow().disconnect(&peer);
            return Ok(());
        }

        let peer_addr = self.service.borrow().get_peer_socket_addr(&peer)?;

        info!(
            "New peer! ID: {:<8}, addr: {:?}",
            HexFmt(peer_key.0),
            peer_addr
        );

        let new_peer = ConnectedPeer::new(peer_key.clone(), peer_addr.ip());
        self.peers.insert(peer_key, new_peer);

        Ok(())
    }

    /// Connects with a found pair.
    fn connect_with_match(
        &mut self,
        name: Option<String>,
        requester_id: PublicEncryptKey,
        found_peer: Option<PublicEncryptKey>,
    ) -> Result<(), Error> {
        if let Some(new_pair) = found_peer {
            let (p2p_conn_info, direct_conn_info) = {
                let requester = self.get_peer_mut(&requester_id)?;
                requester.peers_known.insert(new_pair, PeerStatus::Pending);
                (
                    requester
                        .p2p_conn_info
                        .clone()
                        .ok_or_else(|| Error::PeerNotFound(requester_id.clone()))?,
                    requester
                        .direct_conn_info
                        .clone()
                        .ok_or_else(|| Error::PeerNotFound(requester_id.clone()))?,
                )
            };
            let requester_name = {
                self.get_peer(&requester_id)?
                    .details
                    .as_ref()
                    .and_then(|d| d.name.clone())
            };

            let peer_id = {
                let peer = self.get_peer_mut(&new_pair)?;
                peer.peers_known.insert(requester_id, PeerStatus::Matched);

                Id(peer.id)
            };

            self.send_rpc(
                &peer_id,
                &Rpc::GetPeerReq(
                    if name.is_none() { requester_name } else { name },
                    requester_id,
                    p2p_conn_info,
                    direct_conn_info,
                ),
            )
        } else {
            // No pairing peer was found
            self.send_rpc(&Id(requester_id), &Rpc::GetPeerResp(None, None))
        }
    }

    /// Finds a new random pairing peer for `peer_key` to connect to.
    fn match_peer(&self, peer_key: PublicEncryptKey) -> Option<PublicEncryptKey> {
        let peer_self = if let Ok(peer_self) = self.get_peer(&peer_key) {
            peer_self
        } else {
            return None;
        };
        let mut peer_set: HashSet<_> = self.peers.keys().collect();
        peer_set.remove(&peer_key); // remove self from the randomised selection process

        let known_peers: HashSet<_> = peer_self.peers_known.keys().collect();

        let unknown_peers = peer_set
            .difference(&known_peers)
            // filter out peers that don't have connection info
            .filter(|peer| {
                if let Some(p) = self.peers.get(**peer) {
                    p.p2p_conn_info.is_some() && p.direct_conn_info.is_some() && p.details.is_some()
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        rand::thread_rng()
            .choose(&unknown_peers)
            .map(|peer| (**peer).clone())
    }

    fn add_log(&mut self, log: LogEntry) -> Result<(), Error> {
        stats::output_log(&log)
    }

    fn get_peer(&self, peer_key: &PublicEncryptKey) -> Result<&ConnectedPeer, Error> {
        self.peers
            .get(peer_key)
            .ok_or_else(|| Error::PeerNotFound(peer_key.clone()))
    }

    fn get_peer_mut(&mut self, peer_key: &PublicEncryptKey) -> Result<&mut ConnectedPeer, Error> {
        self.peers
            .get_mut(peer_key)
            .ok_or_else(|| Error::PeerNotFound(peer_key.clone()))
    }

    fn peer_name(&self, peer_key: &PublicEncryptKey) -> String {
        self.get_peer(peer_key)
            .map_err(|_| ())
            .and_then(|p| {
                p.details
                    .as_ref()
                    .and_then(|d| d.name.clone())
                    .ok_or(())
                    .map(|name| format!("{} ({:<8})", name, HexFmt(peer_key.0)))
            }).unwrap_or_else(|_| format!("{:<8}", HexFmt(peer_key.0)))
    }

    fn new_message(&mut self, peer: Id, rpc_cmd: Rpc) -> Result<(), Error> {
        let peer_key = peer.0;
        trace!("RPC from {}: {:?}", self.peer_name(&peer_key), rpc_cmd);

        match rpc_cmd {
            Rpc::UpdateDetails(peer_details) => {
                let json = serde_json::to_string(&peer_details)?;
                info!("UpdateDetails {:<8} {}", HexFmt(peer_key.0), json);

                if &peer_details.version != GIT_COMMIT {
                    info!(
                        "Wrong client version {} used by {}, disconnecting",
                        peer_details.version,
                        self.peer_name(&peer_key)
                    );
                    self.send_rpc(&peer, &Rpc::WrongVersion(GIT_COMMIT.to_owned()))?;
                    self.service.borrow().disconnect(&peer);
                    return Err(Error::WrongPeerVersion(GIT_COMMIT.to_owned()));
                }

                let peer = self.get_peer_mut(&peer_key)?;
                peer.details = Some(peer_details);
            }
            Rpc::ChangeNatType(new_nat_type) => {
                let peer = self.get_peer_mut(&peer_key)?;

                peer.details.as_mut().map(move |prev| {
                    let mut map = HashMap::new();
                    map.insert("from_tcp".to_owned(), prev.nat_type_tcp.clone());
                    map.insert("from_udp".to_owned(), prev.nat_type_udp.clone());
                    map.insert("to_tcp".to_owned(), new_nat_type.nat_type_for_tcp.clone());
                    map.insert("to_udp".to_owned(), new_nat_type.nat_type_for_udp.clone());

                    info!(
                        "ChangeNatType {:<8} {}",
                        HexFmt(peer_key.0),
                        unwrap!(serde_json::to_string(&map))
                    );

                    prev.nat_type_tcp = new_nat_type.nat_type_for_tcp;
                    prev.nat_type_udp = new_nat_type.nat_type_for_udp;
                });
            }
            Rpc::UploadLog(log) => {
                let json = serde_json::to_string(&log)?;
                info!("UploadLog {:<8} {}", HexFmt(peer_key), json);

                let (peer_requester, peer_responder) = {
                    let requester = self.get_peer(&peer_key)?;
                    let responder = self.get_peer(&log.peer)?;

                    // Make sure both requester & responder are connected to each other
                    if !requester.peers_known.contains_key(&log.peer)
                        || !responder.peers_known.contains_key(&peer_key)
                    {
                        return Err(Error::WrongPeerPairing(peer_key, log.peer));
                    }

                    let peer_requester = common::Peer {
                        id: peer_key.0.clone(),
                        name: requester.get_details(|d| d.name.clone())?,
                        ip: if let IpAddr::V4(ip_addr) = self.get_peer(&peer_key)?.addr {
                            ip_addr
                        } else {
                            unimplemented!("IPv6 is not supported");
                        },
                        nat_type: From::from(requester.get_details(|d| d.nat_type())?),
                        os: format!("{}", requester.get_details(|d| d.os.clone())?),
                    };

                    let peer_responder = common::Peer {
                        id: log.peer.0.clone(),
                        name: responder.get_details(|d| d.name.clone())?,
                        ip: if let IpAddr::V4(ip_addr) = self.get_peer(&log.peer)?.addr {
                            ip_addr
                        } else {
                            unimplemented!("IPv6 is not supported")
                        },
                        nat_type: From::from(responder.get_details(|d| d.nat_type())?),
                        os: format!("{}", responder.get_details(|d| d.os.clone())?),
                    };

                    (peer_requester, peer_responder)
                };

                self.add_log(LogEntry {
                    peer_requester,
                    peer_responder,
                    udp_hole_punch_result: From::from(log.udp_hole_punch_result),
                    tcp_hole_punch_result: From::from(log.tcp_hole_punch_result),
                    is_direct_successful: log.is_direct_successful,
                })?;
            }
            Rpc::GetPeerReq(name, _public_id, p2p_conn, direct_conn) => {
                {
                    let peer = self.get_peer_mut(&peer_key)?;
                    peer.p2p_conn_info = Some(p2p_conn);
                    peer.direct_conn_info = Some(direct_conn);
                }
                let pair = self.match_peer(peer_key);

                if let Some(pk) = pair {
                    trace!(
                        "Matching {} with {}",
                        self.peer_name(&peer_key),
                        self.peer_name(&pk),
                    );
                }

                self.connect_with_match(name, peer_key, pair)?;
            }
            Rpc::GetPeerResp(name, Some((_, p2p_connection_info, direct_conn_info))) => {
                // Find pairing peer
                let mut pair_peer_key = None;
                for (peer, status) in &self.get_peer(&peer_key)?.peers_known {
                    trace!("known {} / {:?}", self.peer_name(peer), status);

                    if self.get_peer(&peer)?.peers_known.get(&peer_key)
                        == Some(&PeerStatus::Pending)
                    {
                        // We found the one
                        pair_peer_key = Some(peer.clone());
                        break;
                    }
                }

                if let Some(pair_peer_key) = pair_peer_key {
                    trace!("Connecting with {}", self.peer_name(&pair_peer_key));

                    let pair_peer_id = {
                        let pair_peer = self.get_peer_mut(&pair_peer_key)?;
                        pair_peer.peers_known.insert(peer_key, PeerStatus::Matched);

                        Id(pair_peer.id)
                    };

                    self.send_rpc(
                        &pair_peer_id,
                        &Rpc::GetPeerResp(
                            name,
                            Some((peer_key, p2p_connection_info, direct_conn_info)),
                        ),
                    )?;
                } else {
                    error!("Not found matching peer");
                }
            }
            _ => {
                error!("Received invalid RPC from peer");
            }
        }

        Ok(())
    }
}

fn main() {
    unwrap!(logger::init(true));

    let config = unwrap!(read_config_file());

    let (our_pk, _our_sk) = box_::gen_keypair();

    info!("Our public key is {:<8}", HexFmt(our_pk.0));

    let (category_tx, category_rx) = mpsc::channel();
    let (crust_tx, crust_rx) = mpsc::channel();
    let event_tx =
        MaidSafeObserver::new(crust_tx, MaidSafeEventCategory::Crust, category_tx.clone());
    let mut service = unwrap!(Service::with_config(event_tx, config, Id(our_pk)));

    // Setup listeners
    unwrap!(service.start_listening_tcp());
    if let MaidSafeEventCategory::Crust = unwrap!(category_rx.recv()) {
    } else {
        unreachable!("Unexpected category");
    };
    if let Event::ListenerStarted(port, _igd) = unwrap!(crust_rx.recv()) {
        info!("Listening on port {}", port);
    }

    unwrap!(service.set_accept_bootstrap(true));

    info!("Starting bootstrap proxy");

    // Proxy handling peers and their messages
    let service = Rc::new(RefCell::new(service));
    let mut proxy = Proxy::new(service.clone());

    loop {
        match category_rx.recv() {
            Ok(MaidSafeEventCategory::Crust) => {
                let res = match crust_rx.try_recv() {
                    Ok(Event::NewMessage(peer_id, user, data)) => {
                        if user == CrustUser::Node {
                            warn!(
                                "Attempted to connect Node {:?}, terminating connection",
                                peer_id
                            );
                            service.borrow().disconnect(&peer_id);
                            continue;
                        }
                        let rpc: Rpc = match deserialise(&*data) {
                            Ok(rpc) => rpc,
                            Err(e) => {
                                error!("{}", e);
                                continue;
                            }
                        };
                        proxy.new_message(peer_id, rpc)
                    }
                    Ok(Event::BootstrapAccept(peer_id, user)) => {
                        if user == CrustUser::Node {
                            warn!(
                                "Attempted to connect Node {:?}, terminating connection",
                                peer_id
                            );
                            service.borrow().disconnect(&peer_id);
                            continue;
                        }
                        proxy.new_peer(peer_id)
                    }
                    Ok(Event::LostPeer(peer_id)) => proxy.lost_peer(peer_id),
                    Ok(_) => {
                        // .. do nothing
                        Ok(())
                    }
                    Err(e) => Err(From::from(e)),
                };
                if let Err(e) = res {
                    warn!("{}", e);
                }
            }
            Ok(cat) => {
                warn!("Unexpected category {:?}", cat);
            }
            Err(e) => {
                warn!("{}", e);
            }
        }
    }
}
