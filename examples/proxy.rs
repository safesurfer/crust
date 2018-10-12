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
extern crate tokio_timer;
#[macro_use]
extern crate unwrap;

#[derive(Debug, Default)]
struct StatPairs {
    tcp_failures: u64,
    tcp_succ: u64,
    udp_failures: u64,
    udp_succ: u64,
}

#[derive(Debug, Default)]
struct QuickStats {
    no_hairpin: StatPairs,
    hairpin: StatPairs,
}

static mut STATS: QuickStats = QuickStats {
    no_hairpin: StatPairs {
        tcp_failures: 0,
        tcp_succ: 0,
        udp_failures: 0,
        udp_succ: 0,
    },
    hairpin: StatPairs {
        tcp_failures: 0,
        tcp_succ: 0,
        udp_failures: 0,
        udp_succ: 0,
    },
};

mod common;

use bytes::Bytes;
use clap::{App, Arg};
use common::{NatTraversalResult, Os, Rpc};
use crust::{ConfigFile, CrustError, CrustUser, NatType, PaAddr, Peer, PeerError, Service};
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
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio_core::reactor::{Core, Handle};
use tokio_timer::Interval;

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
    WrongPeerPairing(PublicEncryptKey, PublicEncryptKey),
    PeerNotFound(PublicEncryptKey),
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

impl From<PeerError> for Error {
    fn from(err: PeerError) -> Self {
        Error::Unexpected(format!("{}", err))
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
    LostPeer(PublicEncryptKey),
    Message(PublicEncryptKey, Rpc),
}

#[derive(Eq, PartialEq, Hash, Debug)]
enum PeerStatus {
    Pending,
    Matched,
}

struct Proxy {
    handle: Handle,
    peers: HashMap<PublicEncryptKey, ConnectedPeer>,
    msg_tx: UnboundedSender<Msg>,
}

struct ConnectedPeer {
    id: PublicEncryptKey,
    addr: PaAddr,
    conn_info: Option<RendezvousInfo>,
    nat: Option<NatType>,
    os: Option<Os>,
    name: Option<String>,
    peers_known: HashMap<PublicEncryptKey, PeerStatus>,
    tx: UnboundedSender<Bytes>,
}

impl ConnectedPeer {
    fn new(id: PublicEncryptKey, addr: PaAddr, handle: Handle, sink: SplitSink<Peer>) -> Self {
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

    fn lost_peer(&mut self, peer_key: PublicEncryptKey) -> Result<(), Error> {
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

    fn new_peer(&mut self, peer: Peer) -> Result<(), Error> {
        if self.peers.contains_key(&peer.public_id()) {
            warn!(
                "Peer ID {} attempted to connect once again; dropping connection",
                peer.public_id()
            );
            self.handle
                .spawn(peer.finalize().map_err(|e| error!("{}", e)));
            return Ok(());
        }

        let peer_key = peer.public_id().clone();
        let peer_key2 = peer.public_id().clone();

        let peer_addr = peer.addr()?;

        info!("New peer! ID: {}, addr: {:?}", peer_key, peer_addr);

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
        requester_id: PublicEncryptKey,
        found_peer: Option<PublicEncryptKey>,
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
            peer.peers_known.insert(requester_id, PeerStatus::Matched);

            peer.send_rpc(&Rpc::GetPeerReq(
                if name.is_none() { requester_name } else { name },
                requester_id,
                conn_info,
            ))
        } else {
            // No pairing peer was found
            self.get_peer(&requester_id)?
                .send_rpc(&Rpc::GetPeerResp(None, None))
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
        info!(
            "{} already knows about {:?}",
            self.peer_name(&peer_key),
            known_peers
                .iter()
                .map(|id| self.peer_name(id))
                .collect::<Vec<String>>()
        );
        let unknown_peers = peer_set
            .difference(&known_peers)
            // filter out peers that don't have connection info
            .filter(|peer| {
                if let Some(p) = self.peers.get(**peer) {
                    p.conn_info.is_some() && p.nat.is_some()
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
        let is_hpin = log.peer_requester.ip == log.peer_responder.ip;

        unsafe {
            if let NatTraversalResult::Succeeded = log.udp_hole_punch_result {
                if is_hpin {
                    STATS.hairpin.udp_succ += 1;
                } else {
                    STATS.no_hairpin.udp_succ += 1;
                }
            } else {
                if is_hpin {
                    STATS.hairpin.udp_failures += 1;
                } else {
                    STATS.no_hairpin.udp_failures += 1;
                }
            }

            if let NatTraversalResult::Succeeded = log.tcp_hole_punch_result {
                if is_hpin {
                    STATS.hairpin.tcp_succ += 1;
                } else {
                    STATS.no_hairpin.tcp_succ += 1;
                }
            } else {
                if is_hpin {
                    STATS.hairpin.tcp_failures += 1;
                } else {
                    STATS.no_hairpin.tcp_failures += 1;
                }
            }
        }

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
                p.name
                    .clone()
                    .ok_or(())
                    .map(|name| format!("{} ({})", name, peer_key))
            }).unwrap_or_else(|_| format!("{}", peer_key))
    }

    fn new_message(&mut self, peer_key: PublicEncryptKey, rpc_cmd: Rpc) -> Result<(), Error> {
        trace!("RPC from {}: {:?}", self.peer_name(&peer_key), rpc_cmd);

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
            Rpc::GetPeerReq(name, _public_id, conn) => {
                self.get_peer_mut(&peer_key)?.conn_info = Some(conn);
                let pair = self.match_peer(peer_key);
                info!(
                    "Matching {} with {}",
                    self.peer_name(&peer_key),
                    if let Some(pk) = pair {
                        self.peer_name(&pk)
                    } else {
                        "no one".to_string()
                    }
                );
                self.connect_with_match(name, peer_key, pair)?;
            }
            Rpc::GetPeerResp(name, Some((_, connection_info))) => {
                // Find pairing peer
                let mut pair_peer_key = None;
                for (peer, status) in &self.get_peer(&peer_key)?.peers_known {
                    info!("known {} / {:?}", self.peer_name(peer), status);

                    if self.get_peer(&peer)?.peers_known.get(&peer_key)
                        == Some(&PeerStatus::Pending)
                    {
                        // We found the one
                        pair_peer_key = Some(peer.clone());
                        break;
                    }
                }

                if let Some(pair_peer_key) = pair_peer_key {
                    info!("Connecting with {}", self.peer_name(&pair_peer_key));

                    let pair_peer = self.get_peer_mut(&pair_peer_key)?;
                    pair_peer.peers_known.insert(peer_key, PeerStatus::Matched);
                    pair_peer
                        .send_rpc(&Rpc::GetPeerResp(name, Some((peer_key, connection_info))))?;
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

#[derive(Serialize, Deserialize)]
struct Config {
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

fn read_proxy_config() -> Config {
    let current_bin_dir = unwrap!(config_file_handler::current_bin_dir());
    let mut file = unwrap!(File::open(format!(
        "{}/proxy-config",
        unwrap!(current_bin_dir.as_path().to_str())
    )));
    let mut content = String::new();
    unwrap!(file.read_to_string(&mut content));
    unwrap!(serde_json::from_str(&content))
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

    let proxy_config = read_proxy_config();

    let our_pk = PublicEncryptKey::from_bytes(proxy_config.public_key);
    let our_sk = SecretEncryptKey::from_bytes(proxy_config.secret_key);

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

    // Output stats every 30 seconds
    thread::spawn(move || {
        unsafe {
            let no_hpin = &STATS.no_hairpin;
            let hpin = &STATS.hairpin;

            let tcp_totals = hpin.tcp_failures + hpin.tcp_succ + no_hpin.tcp_failures + no_hpin.tcp_succ;
            let tcp_totals_succ = hpin.tcp_succ + no_hpin.tcp_succ;

            let udp_totals = hpin.udp_failures + hpin.udp_succ + no_hpin.udp_failures + no_hpin.udp_succ;
            let udp_totals_succ = hpin.udp_succ + no_hpin.udp_succ;

            let hpin_tcp_totals = hpin.tcp_failures + hpin.tcp_succ;
            let hpin_udp_totals = hpin.udp_failures + hpin.udp_succ;

            let no_hpin_tcp_totals = no_hpin.tcp_failures + no_hpin.tcp_succ;
            let no_hpin_udp_totals = no_hpin.udp_failures + no_hpin.udp_succ;

            let hpin_stats = if hpin_tcp_totals > 0 || hpin_udp_totals > 0 {
                format!("TCP (only hairpinning) %: {}, UDP (only hairpinning) %: {}\n",
                        if hpin_tcp_totals > 0 {
                            ((hpin.tcp_succ as f64 / hpin_tcp_totals as f64) * 100.0).round()
                        } else {
                            0.0
                        },
                        if hpin_udp_totals > 0 {
                            ((hpin.udp_succ as f64 / hpin_udp_totals as f64) * 100.0).round()
                        } else {
                            0.0
                        }
                )
            } else {
                "".to_owned()
            };

            info!(
                "\nHole Punching Stats:\n{:#?}.\n\nSuccess stats:\nTCP (excluding hairpinning) %: {}, UDP (excluding hairpinning) %: {}\n{}TCP (combined) %: {}, UDP (combined) %: {}\n",
                STATS,
                if no_hpin_tcp_totals > 0 {
                    ((no_hpin.tcp_succ as f64 / no_hpin_tcp_totals as f64) * 100.0).round()
                } else {
                    0.0
                },
                if no_hpin_udp_totals > 0 {
                    ((no_hpin.udp_succ as f64 / no_hpin_udp_totals as f64) * 100.0).round()
                } else {
                    0.0
                },
                hpin_stats,
                if tcp_totals > 0 {
                    ((tcp_totals_succ as f64 / tcp_totals as f64) * 100.0).round()
                } else {
                    0.0
                },
                if udp_totals > 0 {
                    ((udp_totals_succ as f64 / udp_totals as f64) * 100.0).round()
                } else {
                    0.0
                },
            );
        }

        thread::sleep(Duration::from_secs(30));
    );

    // Setup listeners
    service.start_listening_tcp();

    loop {
        match category_rx.recv() {
            Ok(MaidSafeEventCategory::Routing) => match app_msg_rx.try_recv() {
                Err(e) => {
                    error!("{}", e);
                    break;
                }
                Ok(msg) => {
                    /*
                    let res = match msg {
                        Msg::RetryConnect => client.await_peer(),
                        Msg::ConnectedWithPeer(peer_id, full_stats, send_stats) => {
                            client.report_connection_result(peer_id, full_stats, send_stats)
                        }
                    };
                    if let Err(e) = res {
                        error!("{}", e);
                    }
*/
                }
            },
            Ok(MaidSafeEventCategory::Crust) => match crust_rx.try_recv() {
                Ok(_) => {
                    // .. do nothing
                }
                Ok(Event::NewMessage(peer_id, _user, data)) => {
                    let rpc: Rpc = unwrap!(deserialise(&data));
                    unwrap!(client.handle_new_message(rpc));
                }
                Ok(Event::BootstrapAccept(peer_id, user)) => {
                    if user == CrustUser::Node {
                        warn!(
                            "Attempted to connect Node {:?}, terminating connection",
                            peer_id
                        );
                        service.disconnect(peer_id);
                        continue;
                    }
                    proxy.new_peer(peer_id);
                }
                Ok(Event::LostPeer(peer_id)) => {
                    proxy.lost_peer(peer_id);
                }
                Err(e) => {
                    error!("{}", e);
                    break;
                }
            },
            Err(e) => {
                error!("{}", e);
                break;
            }
        }
    }
}
