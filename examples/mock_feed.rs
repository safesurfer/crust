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
extern crate crust;
extern crate safe_crypto;

mod common;

use common::{NatTraversalResult, Os, Peer, Rpc};
use crust::NatType;
use maidsafe_utilities::{
    log as logger,
    serialisation::{deserialise, serialise},
};
use rand::{Rand, Rng};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct LogEntry {
    peer_requester: Peer,
    peer_responder: Peer,
    is_direct_successful: bool,
    utp_hole_punch_result: NatTraversalResult,
    tcp_hole_punch_result: NatTraversalResult,
}

fn rand_nat_type<R: rand::Rng>(rng: &mut R) -> NatType {
    unwrap!(rng.choose(&[
        NatType::EIM,
        NatType::EDM,
        NatType::EDMRandomPorts(vec![1, 2, 3]),
    ])).clone()
}

impl Rand for Peer {
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        Peer {
            ip: Ipv4Addr::new(
                rng.gen_range(0, 255),
                rng.gen_range(0, 255),
                rng.gen_range(0, 255),
                rng.gen_range(0, 255),
            ),
            nat_type: rand_nat_type(rng),
            os: unwrap!(rng.choose(&["windows", "macos", "linux"])).to_string(),
        }
    }
}

impl Rand for NatTraversalResult {
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        let failed: bool = rng.gen();
        if failed {
            NatTraversalResult::Failed
        } else {
            NatTraversalResult::Succeeded {
                time_spent: Duration::from_millis(rng.gen_range(50, 1000)),
            }
        }
    }
}

mod stats {
    use serde_json;
    use LogEntry;

    pub fn output_log(log: &LogEntry) {
        let json = unwrap!(serde_json::to_string(log));
        info!("{}", json);
    }
}

fn main() {
    unwrap!(logger::init(true));

    loop {
        stats::output_log(&LogEntry {
            is_direct_successful: rand::random(),
            peer_requester: rand::random(),
            peer_responder: rand::random(),
            utp_hole_punch_result: rand::random(),
            tcp_hole_punch_result: rand::random(),
        });
        thread::sleep(Duration::from_secs(3));
    }
}
