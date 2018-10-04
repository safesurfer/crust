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

use crust::NatType;
use p2p_old::RendezvousInfo;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

// With custom Eq/PartialEq implemented to discard `NatTraversalResult::time_spent` as we don't want to account for that in HashSet dedups
#[derive(Serialize, Deserialize, Debug)]
pub enum NatTraversalResult {
    Failed,
    Succeeded,
}

impl PartialEq for NatTraversalResult {
    fn eq(&self, other: &NatTraversalResult) -> bool {
        match (self, other) {
            (NatTraversalResult::Failed, NatTraversalResult::Failed) => true,
            (NatTraversalResult::Succeeded, NatTraversalResult::Succeeded) => true,
            _ => false,
        }
    }
}

impl Eq for NatTraversalResult {}

impl Hash for NatTraversalResult {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            NatTraversalResult::Failed => 0.hash(state),
            NatTraversalResult::Succeeded { .. } => 1.hash(state),
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
    pub peer: [u8; 32], // PublicEncryptKey, // TODO: force IP address here; allow only the one we use to connect with the proxy
    pub udp_hole_punch_result: NatTraversalResult,
    pub tcp_hole_punch_result: NatTraversalResult,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Rpc {
    UpdateDetails {
        name: Option<String>,
        nat: NatType,
        os: Os,
    },
    GetPeerReq(Option<String>, RendezvousInfo),
    GetPeerResp(Option<String>, Option<(RendezvousInfo)>),
    UploadLog(LogUpdate),
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
