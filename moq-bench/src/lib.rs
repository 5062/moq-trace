//! Implementation-independent MoQ peers for cross-implementation trace measurements.
//!
//! Every experiment compares relays this toolkit does not own, which only holds up
//! if the peers are the constant side of the measurement: one pinned protocol
//! version, one implementation, and no relay policy that can vary between runs.
//!
//! The server is a reflexive origin with no auth, cluster, or cache. The client is
//! a synthetic workload driver. Both are built from the same `moq-net` and
//! `moq-native`, so their sessions exercise the toolkit's instrumentation sites the
//! same way and produce comparable traces.
//!
//! These peers are a fixture and a baseline, never a comparison row of their own.
//! See `README.md` for the roles they play.

#![warn(missing_docs)]

pub mod object;
pub mod publish;
pub mod stats;
pub mod subscribe;

use std::str::FromStr;

use moq_net::Versions;

/// The MoQ version every bench peer speaks.
///
/// MoQ-lite and the other IETF drafts are deliberately unreachable. A peer that
/// negotiated a different version would silently produce a trace that cannot be
/// compared with the rest of the matrix.
pub const VERSION: &str = "moq-transport-16";

/// Install the process-wide rustls crypto provider.
///
/// `moq-native` builds rustls with `aws-lc-rs`, and rustls only selects a default
/// provider when exactly one is linked. Installing it explicitly keeps the choice
/// from depending on the rest of the dependency tree.
pub fn install_crypto() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no other process-wide crypto provider is installed");
}

/// The single MoQ version set both peers offer and accept.
#[must_use]
pub fn versions() -> Versions {
    let version = moq_net::Version::from_str(VERSION).expect("VERSION is a known MoQ version");
    Versions::from(vec![version])
}

/// The synthetic object shape a publisher emits.
///
/// Every frame in a group is exactly `frame_size` bytes, the JSON keyframe
/// included, so object size stays a clean independent variable across runs.
#[derive(clap::Args, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Shape {
    /// Frames emitted per second per track. Zero publishes the track but stays idle.
    #[arg(long, env = "MOQ_BENCH_FPS", default_value_t = Shape::default().fps)]
    pub fps: u64,
    /// Bytes per frame.
    #[arg(long, env = "MOQ_BENCH_FRAME_SIZE", default_value_t = Shape::default().frame_size)]
    pub frame_size: u64,
    /// Zeroed frames per group following the keyframe. May be zero.
    #[arg(long, env = "MOQ_BENCH_GROUP_SIZE", default_value_t = Shape::default().group_size)]
    pub group_size: u64,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            fps: 30,
            frame_size: 16_384,
            group_size: 0,
        }
    }
}
