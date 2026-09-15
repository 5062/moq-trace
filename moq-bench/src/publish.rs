//! Synthetic group production.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moq_net::bytes::Bytes;
use moq_net::{Timestamp, track};

use crate::Shape;
use crate::object::Header;
use crate::stats::Stats;

/// Produce frames on one track until the process exits.
///
/// Each group opens with the JSON keyframe describing the shape, then carries
/// `group_size` zeroed frames. The loop never returns: a track that stopped
/// producing should still stay published, and the caller holds it open instead.
pub async fn produce(
    path: String,
    shape: Shape,
    mut track: track::Producer,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    // An idle track stays published without producing, which is how a run isolates
    // the control plane. Returning a pending future avoids a division by zero below.
    if shape.fps == 0 {
        return std::future::pending::<anyhow::Result<()>>().await;
    }

    let zeros = Bytes::from(vec![0u8; shape.frame_size as usize]);
    let period = Duration::from_secs_f64(1.0 / shape.fps as f64);
    let mut ticker = tokio::time::interval(period);
    // A stalled tick delays the next frame rather than queueing a burst to catch up,
    // so a scheduling hiccup cannot inflate the offered load.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut sequence = 0;
    loop {
        let mut group = track.append_group()?;

        ticker.tick().await;
        let header = Header {
            broadcast: path.clone(),
            group: sequence,
            fps: shape.fps,
            frame_size: shape.frame_size,
            group_size: shape.group_size,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        };
        let keyframe = header.encode(shape.frame_size)?;
        stats.frame_sent(keyframe.len());
        group.write_frame(Timestamp::now(), keyframe)?;

        for _ in 0..shape.group_size {
            ticker.tick().await;
            stats.frame_sent(zeros.len());
            group.write_frame(Timestamp::now(), zeros.clone())?;
        }

        stats.group_sent();
        group.finish()?;
        sequence += 1;
    }
}
