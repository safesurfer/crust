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

//! Common utils for the bootstrap server and client.

pub mod event_loop;

use crust::Uid;
use p2p::{NatType as P2pNatType, RendezvousInfo};
use safe_crypto::PublicEncryptKey;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize, Debug)]
pub struct Id(pub PublicEncryptKey);
impl Uid for Id {}

// With custom Eq/PartialEq implemented to discard `NatTraversalResult::time_spent` as we don't want to account for that in HashSet dedups
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub enum NatTraversalResult {
    Failed,
    Succeeded,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TcpNatTraversalResult {
    Failed,
    Succeeded { time_spent: Duration },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UdpNatTraversalResult {
    Failed,
    Succeeded {
        time_spent: Duration,
        starting_ttl: u32,
        ttl_on_being_reached: u32,
    },
}

impl From<TcpNatTraversalResult> for NatTraversalResult {
    fn from(nat_res: TcpNatTraversalResult) -> Self {
        match nat_res {
            TcpNatTraversalResult::Failed => NatTraversalResult::Failed,
            TcpNatTraversalResult::Succeeded { .. } => NatTraversalResult::Succeeded,
        }
    }
}

impl From<UdpNatTraversalResult> for NatTraversalResult {
    fn from(nat_res: UdpNatTraversalResult) -> Self {
        match nat_res {
            UdpNatTraversalResult::Failed => NatTraversalResult::Failed,
            UdpNatTraversalResult::Succeeded { .. } => NatTraversalResult::Succeeded,
        }
    }
}

/// Network Address Translation type that the front-end expects
#[derive(Debug, Hash, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum NatType {
    /// We failed to detect NAT type.
    Unknown,
    /// No NAT - direct connection is possible.
    None,
    /// Endpoint Independent Mapping
    EIM,
    /// Endpoint Dependent Mapping where we can guess a next port.
    EDM,
    /// Endpoint Dependent Mapping with unpredictable port allocation.
    EDMRandomPorts(Vec<u16>),
}

impl<'a> From<&'a P2pNatType> for NatType {
    fn from(p2p_nat_type: &P2pNatType) -> Self {
        match p2p_nat_type {
            P2pNatType::EIM => NatType::EIM,
            P2pNatType::EDM(_delta) => NatType::EDM,
            P2pNatType::EDMRandomPort(ports) => NatType::EDMRandomPorts(ports.clone()),
            P2pNatType::EDMRandomIp(_ips) => NatType::EDM,
            P2pNatType::Unknown => NatType::Unknown,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub nat_type: NatType,
    pub os: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogUpdate {
    pub peer: PublicEncryptKey,
    pub udp_hole_punch_result: UdpNatTraversalResult,
    pub tcp_hole_punch_result: TcpNatTraversalResult,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerDetails {
    pub name: Option<String>,
    pub nat_type_tcp: P2pNatType,
    pub nat_type_udp: P2pNatType,
    pub os: Os,
    pub upnp: bool,
    pub version: String,
}

impl PeerDetails {
    pub fn nat_type(&self) -> NatType {
        From::from(match (&self.nat_type_tcp, &self.nat_type_udp) {
            (P2pNatType::Unknown, udp) => udp,
            (tcp, P2pNatType::Unknown) => tcp,
            (tcp, udp) if tcp == udp => tcp,
            (_tcp, udp) => udp,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Rpc {
    UpdateDetails(PeerDetails),
    GetPeerReq(Option<String>, PublicEncryptKey, RendezvousInfo),
    GetPeerResp(Option<String>, Option<(PublicEncryptKey, RendezvousInfo)>),
    UploadLog(LogUpdate),
    WrongVersion(String),
}

impl fmt::Display for Rpc {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use Rpc::*;
        match self {
            UpdateDetails { .. } => write!(fmt, "UpdateDetails"),
            GetPeerReq(..) => write!(fmt, "GetPeerReq"),
            GetPeerResp(_, opt) => write!(
                fmt,
                "GetPeerResp({})",
                if opt.is_none() { "None" } else { "Some" }
            ),
            UploadLog(..) => write!(fmt, "UploadLog"),
            WrongVersion(..) => write!(fmt, "WrongVersion"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
    Unknown,
}

impl fmt::Display for Os {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use Os::*;
        write!(
            fmt,
            "{}",
            match self {
                Linux => "linux",
                MacOs => "macos",
                Windows => "windows",
                Unknown => "unknown",
            }
        )
    }
}
