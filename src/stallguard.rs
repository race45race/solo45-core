//! Stall guard (port of Solo45's stallguard.py): when the node has seen a new block announced but one peer is
//! holding up its download, disconnect that peer long before Bitcoin Core's own 10-minute timeout, so the node
//! fetches the block from another peer and the miners stop working on an old block.
//!
//! It only ever disconnects a peer (the node replaces it by itself). It never bans, and it stays out of the way
//! while the node is catching up on many blocks, for example after it was switched off.

use serde_json::{json, Value};
use std::collections::HashSet;

pub const MAX_GAP: u64 = 3; // only act when the node is 1-3 blocks behind the announced chain
pub const COOLDOWN_S: f64 = 30.0; // at most one round of disconnects per 30 s
const KEEP_EVENTS: usize = 20;

#[derive(Default)]
pub struct StallGuard {
    behind_since: Option<f64>, // when the node was first seen behind the announced chain
    last_blocks: u64,          // the node's height at the last check: a new block restarts the clock
    last_action: f64,
    warned_idle: bool, // already logged "behind, but no peer has the block in flight"
    pub events: Vec<Value>, // newest last, saved in state.json as "stall_events"
}

impl StallGuard {
    pub fn new(events: Vec<Value>) -> StallGuard {
        StallGuard { events, ..Default::default() }
    }

    /// Decide what to do. Returns the peers to disconnect as (id, description), and a note to log.
    pub fn check(&mut self, blocks: u64, headers: u64, ibd: bool, peers: &[Value], now: f64, limit_s: f64)
                 -> (Vec<(i64, String)>, Option<String>) {
        if limit_s <= 0.0 || ibd || headers <= blocks || headers - blocks > MAX_GAP {
            self.behind_since = None;
            self.warned_idle = false;
            return (vec![], None);
        }
        if blocks != self.last_blocks {
            // the node got a block: whatever it waits for now (the next one, announced right after) waits from now,
            // not from when the previous block stalled
            self.last_blocks = blocks;
            self.behind_since = None;
            self.warned_idle = false;
        }
        let since = *self.behind_since.get_or_insert(now);
        let waited = now - since;
        if waited < limit_s || now - self.last_action < COOLDOWN_S {
            return (vec![], None);
        }
        let missing: HashSet<u64> = (blocks + 1..=headers).collect();
        let targets: Vec<&Value> = peers.iter()
            .filter(|p| p["inflight"].as_array().map_or(false, |a| a.iter().any(|h| h.as_u64().map_or(false, |h| missing.contains(&h)))))
            .collect();
        if targets.is_empty() {
            if self.warned_idle {
                return (vec![], None);
            }
            self.warned_idle = true;
            return (vec![], Some(format!(
                "the node is {} block(s) behind for {:.0} s, but no peer has the block in flight (it may still be checking a large block)",
                headers - blocks, waited)));
        }
        self.last_action = now;
        let out: Vec<(i64, String)> = targets.iter().filter_map(|p| {
            let id = p["id"].as_i64()?;
            Some((id, format!("peer {} ({}, {})", id, p["network"].as_str().unwrap_or("?"),
                              if p["inbound"].as_bool().unwrap_or(false) { "inbound" } else { "outbound" })))
        }).collect();
        self.events.push(json!({"at": now, "height": blocks + 1, "waited_s": waited.round(),
                                "peers": out.iter().map(|(_, d)| d.clone()).collect::<Vec<_>>()}));
        if self.events.len() > KEEP_EVENTS {
            let drop = self.events.len() - KEEP_EVENTS;
            self.events.drain(..drop);
        }
        (out, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: i64, inflight: &[u64]) -> Value {
        json!({"id": id, "network": "ipv4", "inbound": id % 2 == 0, "inflight": inflight})
    }

    #[test]
    fn waits_then_drops_only_the_peer_holding_the_block() {
        let mut g = StallGuard::default();
        let peers = [peer(7, &[101]), peer(8, &[]), peer(9, &[99])];
        assert!(g.check(100, 101, false, &peers, 1000.0, 60.0).0.is_empty()); // starts the clock
        assert!(g.check(100, 101, false, &peers, 1059.0, 60.0).0.is_empty()); // not yet
        let (out, note) = g.check(100, 101, false, &peers, 1060.0, 60.0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 7);
        assert!(out[0].1.contains("outbound"));
        assert!(note.is_none());
        assert_eq!(g.events.len(), 1);
        assert_eq!(g.events[0]["height"], 101);
        // cooldown: nothing again for 30 s
        assert!(g.check(100, 101, false, &peers, 1080.0, 60.0).0.is_empty());
        assert_eq!(g.check(100, 101, false, &peers, 1091.0, 60.0).0.len(), 1);
    }

    #[test]
    fn stays_out_of_the_way() {
        let mut g = StallGuard::default();
        let peers = [peer(1, &[101, 102, 103, 104])];
        // off, catching up (ibd), level, or too far behind: never acts and never starts the clock
        for (b, h, ibd, lim) in [(100, 101, false, 0.0), (100, 101, true, 60.0), (100, 100, false, 60.0), (100, 104, false, 60.0)] {
            assert!(g.check(b, h, ibd, &peers, 0.0, lim).0.is_empty());
            assert!(g.check(b, h, ibd, &peers, 1000.0, lim).0.is_empty());
        }
        // the block arrives: the clock resets
        assert!(g.check(100, 101, false, &peers, 2000.0, 60.0).0.is_empty());
        assert!(g.check(101, 101, false, &peers, 2050.0, 60.0).0.is_empty());
        assert!(g.check(101, 102, false, &peers, 2070.0, 60.0).0.is_empty()); // a new wait, not 70 s
    }

    #[test]
    fn a_block_that_arrives_restarts_the_clock_for_the_next() {
        let mut g = StallGuard::default();
        let peers = [peer(5, &[102])];
        assert!(g.check(100, 101, false, &peers, 0.0, 60.0).0.is_empty()); // block 101 stalls...
        assert!(g.check(100, 101, false, &peers, 55.0, 60.0).0.is_empty());
        // ...arrives at 58 s, and 102 is announced before the next check: 102 waits from now, not from 0 s
        assert!(g.check(101, 102, false, &peers, 60.0, 60.0).0.is_empty());
        assert!(g.check(101, 102, false, &peers, 119.0, 60.0).0.is_empty());
        assert_eq!(g.check(101, 102, false, &peers, 120.0, 60.0).0.len(), 1);
    }

    #[test]
    fn notes_once_when_nobody_has_the_block_in_flight() {
        let mut g = StallGuard::default();
        let peers = [peer(1, &[]), peer(2, &[50])];
        g.check(100, 101, false, &peers, 0.0, 60.0);
        let (out, note) = g.check(100, 101, false, &peers, 61.0, 60.0);
        assert!(out.is_empty());
        assert!(note.unwrap().contains("no peer has the block in flight"));
        assert!(g.check(100, 101, false, &peers, 70.0, 60.0).1.is_none()); // only once
    }

    #[test]
    fn keeps_the_last_20_events() {
        let mut g = StallGuard::default();
        let peers = [peer(3, &[101])];
        g.check(100, 101, false, &peers, 0.0, 20.0);
        for i in 0..25 {
            g.check(100, 101, false, &peers, 20.0 + 30.0 * i as f64, 20.0);
        }
        assert_eq!(g.events.len(), 20);
    }
}
