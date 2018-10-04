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

extern crate mio;
extern crate p2p_old;
extern crate rust_sodium;

extern crate bytes;
extern crate clap;
extern crate crust;
extern crate future_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate rand;
extern crate safe_crypto;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

// pub type PublicEncryptKey = [u8; 32];

mod common;

use bytes::Bytes;
use clap::{App, Arg};
use common::{NatTraversalResult, Os, Rpc};
use crust::{ConfigFile, CrustError, CrustUser, NatType, PaAddr, Peer, PubConnectionInfo, Service};
use futures::sync::mpsc::{self, UnboundedSender};
use futures::{future::empty, stream::SplitSink, Future, Sink, Stream};
use maidsafe_utilities::{
    log as logger,
    serialisation::{deserialise, serialise},
};
use p2p_old::RendezvousInfo;
use rand::Rng;
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use tokio_core::reactor::{Core, Handle};

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
    Unexpected(String),
    PartialPeerInfo,
    WrongPeerPairing([u8; 32], [u8; 32]),
    PeerNotFound([u8; 32]),
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
}

#[derive(Debug)]
enum Msg {
    NewPeer(Peer),
    LostPeer([u8; 32]),
    Message([u8; 32], Rpc),
}

#[derive(Eq, PartialEq, Hash, Debug)]
enum PeerStatus {
    Pending,
    Established, // FIXME: rename
}

struct Proxy {
    handle: Handle,
    peers: HashMap<[u8; 32], ConnectedPeer>,
    msg_tx: UnboundedSender<Msg>,
}

struct ConnectedPeer {
    id: [u8; 32],
    addr: PaAddr,
    conn_info: Option<RendezvousInfo>,
    nat: Option<NatType>,
    os: Option<Os>,
    name: Option<String>,
    peers_known: HashMap<[u8; 32], PeerStatus>,
    tx: UnboundedSender<Bytes>,
}

impl ConnectedPeer {
    fn new(id: [u8; 32], addr: PaAddr, handle: Handle, sink: SplitSink<Peer>) -> Self {
        let (tx, rx) = mpsc::unbounded::<Bytes>();
        handle.spawn(sink.sink_map_err(|_| ()).send_all(rx).then(move |_| Ok(())));

        ConnectedPeer {
            id,
            addr,
            tx,
            name: None,
            nat: None,
            os: None,
            peers_known: HashMap::default(),
            conn_info: None,
        }
    }

    fn send_rpc(&self, rpc: &Rpc) -> Result<(), Error> {
        let bytes = unwrap!(serialise(rpc));
        self.tx
            .unbounded_send(Bytes::from(bytes))
            .map_err(|e| From::from(format!("{}", e)))
    }
}

impl Proxy {
    fn new(handle: Handle, msg_tx: UnboundedSender<Msg>) -> Self {
        Proxy {
            handle,
            peers: Default::default(),
            msg_tx,
        }
    }

    fn tx(&self) -> UnboundedSender<Msg> {
        self.msg_tx.clone()
    }

    fn lost_peer(&mut self, peer_key: [u8; 32]) -> Result<(), Error> {
        info!("Disconnected peer {:?}", peer_key);

        let _ = self.peers.remove(&peer_key);
        let mut needs_new_pair = None;

        for peer in self.peers.values_mut() {
            let status = peer.peers_known.remove(&peer_key);
            if let Some(PeerStatus::Pending) = status {
                needs_new_pair = Some(peer.id);
            }
        }

        // Find a new pair for a peer that was lost due to a connection
        if let Some(peer_key) = needs_new_pair {
            let pair = self.match_peer(peer_key);
            self.connect_with_match(None, peer_key, pair)?;
        }

        Ok(())
    }

    fn new_peer(&mut self, peer: Peer) -> Result<(), Error> {
        if self.peers.contains_key(&peer.public_id().into_bytes()) {
            warn!(
                "Peer ID {} attempted to connect once again; dropping connection",
                peer.public_id()
            );
            self.handle
                .spawn(peer.finalize().map_err(|e| error!("{}", e)));
            return Ok(());
        }

        info!(
            "New peer! ID: {}, addr: {:?}",
            peer.public_id(),
            unwrap!(peer.addr())
        );

        let peer_key = peer.public_id().into_bytes();
        let peer_key2 = peer.public_id().into_bytes();
        let peer_addr = unwrap!(peer.addr());

        let (peer_sink, peer_stream) = peer.split();

        let new_peer =
            ConnectedPeer::new(peer_key.clone(), peer_addr, self.handle.clone(), peer_sink);
        self.peers.insert(peer_key, new_peer);

        let msg_tx = self.tx();
        let msg_tx2 = self.tx();

        self.handle.spawn(
            peer_stream
                .for_each(move |bytes| {
                    match deserialise(&*bytes) {
                        Ok(rpc) => {
                            unwrap!(msg_tx.unbounded_send(Msg::Message(peer_key, rpc)));
                        }
                        Err(e) => {
                            error!("{}", e);
                        }
                    }
                    Ok(())
                }).then(move |_| {
                    unwrap!(msg_tx2.unbounded_send(Msg::LostPeer(peer_key2)));
                    Ok(())
                }),
        );

        Ok(())
    }

    /// Connects with a found pair.
    fn connect_with_match(
        &mut self,
        name: Option<String>,
        requester_id: [u8; 32],
        found_peer: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        if let Some(new_pair) = found_peer {
            let conn_info = {
                let requester = self.get_peer_mut(&requester_id)?;
                requester.peers_known.insert(new_pair, PeerStatus::Pending);
                requester
                    .conn_info
                    .as_ref()
                    .ok_or_else(|| Error::PeerNotFound(requester_id.clone()))?
                    .clone()
            };
            let requester_name = { self.get_peer(&requester_id)?.name.clone() };

            let peer = self.get_peer_mut(&new_pair)?;
            peer.peers_known
                .insert(requester_id, PeerStatus::Established);

            peer.send_rpc(&Rpc::GetPeerReq(
                if name.is_none() { requester_name } else { name },
                conn_info,
            ))
        } else {
            // No pairing peer was found
            self.get_peer(&requester_id)?
                .send_rpc(&Rpc::GetPeerResp(None, None))
        }
    }

    /// Finds a new random pairing peer for `peer_key` to connect to.
    fn match_peer(&self, peer_key: [u8; 32]) -> Option<[u8; 32]> {
        let peer_self = unwrap!(self.get_peer(&peer_key));

        let mut peer_set: HashSet<_> = self.peers.keys().collect();
        peer_set.remove(&peer_key); // remove self from the randomised selection process

        let known_peers: HashSet<_> = peer_self.peers_known.keys().collect();
        info!(
            "{:?} already knows about {:?}",
            peer_key,
            known_peers
                .iter()
                .map(|id| format!("{:?}", id))
                .collect::<Vec<String>>()
        );
        let unknown_peers = peer_set
            .difference(&known_peers)
            // filter out peers that don't have connection info
            .filter(|peer| {
                let p = unwrap!(self.peers.get(**peer));
                p.conn_info.is_some() && p.nat.is_some()
            })
            .collect::<Vec<_>>();

        rand::thread_rng()
            .choose(&unknown_peers)
            .map(|peer| (**peer).clone())
    }

    fn add_log(&mut self, log: LogEntry) -> Result<(), Error> {
        stats::output_log(&log)
    }

    fn get_peer(&self, peer_key: &[u8; 32]) -> Result<&ConnectedPeer, Error> {
        self.peers
            .get(peer_key)
            .ok_or_else(|| Error::PeerNotFound(peer_key.clone()))
    }

    fn get_peer_mut(&mut self, peer_key: &[u8; 32]) -> Result<&mut ConnectedPeer, Error> {
        self.peers
            .get_mut(peer_key)
            .ok_or_else(|| Error::PeerNotFound(peer_key.clone()))
    }

    fn new_message(&mut self, peer_key: [u8; 32], rpc_cmd: Rpc) -> Result<(), Error> {
        info!("got rpc {:?} from peer {:?}", rpc_cmd, peer_key);

        match rpc_cmd {
            Rpc::UpdateDetails { name, nat, os } => {
                let peer = self.get_peer_mut(&peer_key)?;
                peer.nat = Some(nat);
                peer.os = Some(os);
                peer.name = name;
            }
            Rpc::UploadLog(log) => {
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
                        ip: if let IpAddr::V4(ip_addr) = self.get_peer(&peer_key)?.addr.ip() {
                            ip_addr
                        } else {
                            unimplemented!("IPv6 is not supported");
                        },
                        nat_type: requester.nat.clone().ok_or(Error::PartialPeerInfo)?,
                        os: format!("{}", requester.os.clone().ok_or(Error::PartialPeerInfo)?),
                    };

                    let peer_responder = common::Peer {
                        ip: if let IpAddr::V4(ip_addr) = self.get_peer(&log.peer)?.addr.ip() {
                            ip_addr
                        } else {
                            unimplemented!("IPv6 is not supported")
                        },
                        nat_type: responder.nat.clone().ok_or(Error::PartialPeerInfo)?,
                        os: format!("{}", responder.os.clone().ok_or(Error::PartialPeerInfo)?),
                    };

                    (peer_requester, peer_responder)
                };

                self.add_log(LogEntry {
                    peer_requester,
                    peer_responder,
                    udp_hole_punch_result: log.udp_hole_punch_result,
                    tcp_hole_punch_result: log.tcp_hole_punch_result,
                })?;
            }
            Rpc::GetPeerReq(name, conn) => {
                self.get_peer_mut(&peer_key)?.conn_info = Some(conn);
                let pair = self.match_peer(peer_key);
                info!(
                    "Matching {:?} with {}",
                    peer_key,
                    if let Some(pk) = pair {
                        format!("{:?}", pk)
                    } else {
                        "no one".to_string()
                    }
                );
                self.connect_with_match(name, peer_key, pair)?;
            }
            Rpc::GetPeerResp(name, info) => {
                // Find pairing peer
                let mut pair_peer_key = None;
                for (peer, status) in &self.get_peer(&peer_key)?.peers_known {
                    info!("known {:?} / {:?}", peer, status);

                    if self.get_peer(&peer)?.peers_known.get(&peer_key)
                        == Some(&PeerStatus::Pending)
                    {
                        // We found the one
                        pair_peer_key = Some(peer.clone());
                        break;
                    }
                }

                if let Some(pair_peer_key) = pair_peer_key {
                    info!("Connecting with {:?}", pair_peer_key);

                    let pair_peer = self.get_peer_mut(&pair_peer_key)?;
                    pair_peer
                        .peers_known
                        .insert(peer_key, PeerStatus::Established);
                    pair_peer.send_rpc(&Rpc::GetPeerResp(name, info))?;
                } else {
                    error!("Not found matching peer");
                }
            }
        }

        Ok(())
    }
}

fn main() {
    unwrap!(logger::init(true));

    let matches = App::new("Crust Proxy")
        .author("MaidSafe Developers <dev@maidsafe.net>")
        .about("Runs the bootstrap matching server")
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .takes_value(true)
                .help("Config file path"),
        ).get_matches();

    let config = unwrap!(if let Some(cfg_path) = matches.value_of("config") {
        info!("Loading config from {}", cfg_path);
        ConfigFile::open_path(From::from(cfg_path))
    } else {
        ConfigFile::open_default()
    });

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();

    let our_pk = PublicEncryptKey::from_bytes([
        136, 225, 216, 0, 112, 223, 59, 247, 97, 60, 231, 203, 1, 155, 95, 99, 197, 221, 127, 206,
        181, 223, 155, 113, 142, 180, 211, 80, 144, 71, 244, 104,
    ]);
    let our_sk = SecretEncryptKey::from_bytes([
        167, 64, 194, 202, 108, 93, 240, 47, 241, 95, 23, 16, 180, 204, 223, 174, 161, 1, 156, 102,
        20, 212, 115, 170, 221, 177, 205, 150, 111, 161, 119, 43,
    ]);

    info!("Our public key is {:?}", our_pk);

    let mut svc = unwrap!(event_loop.run(Service::with_config(&handle, config, our_sk, our_pk)));

    info!("Starting bootstrap proxy");

    // Proxy handling peers and their messages
    let (proxy_tx, proxy_rx) = mpsc::unbounded();
    let mut proxy = Proxy::new(handle.clone(), proxy_tx.clone());

    handle.spawn(proxy_rx.for_each(move |msg| {
        let res = match msg {
            Msg::NewPeer(peer) => proxy.new_peer(peer),
            Msg::LostPeer(peer) => proxy.lost_peer(peer),
            Msg::Message(id, rpc) => proxy.new_message(id, rpc),
        };
        if let Err(e) = res {
            error!("{}", e);
        }
        Ok(())
    }));

    // Setup bootstrap proxy
    let handle2 = handle.clone();

    handle.spawn(
        svc.bootstrap_acceptor()
            .for_each(move |peer| {
                if peer.kind() == CrustUser::Node {
                    warn!(
                        "Attempted to connect Node {:?}, terminating connection",
                        peer
                    );
                    handle2.spawn(peer.finalize().map_err(|e| error!("{}", e)));
                    return Ok(());
                }
                unwrap!(proxy_tx.unbounded_send(Msg::NewPeer(peer)));
                Ok(())
            }).then(|_| Ok(())),
    );

    // Setup listeners
    let listeners = unwrap!(event_loop.run(svc.start_listening().collect()));
    for listener in &listeners {
        info!("Listening on {}", listener.addr());
    }

    unwrap!(event_loop.run(empty::<(), ()>()));
}
