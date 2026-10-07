//! Synthetic group production.

use std::sync::Arc;
use std::time::Duration;

use moq_net::bytes::Bytes;
use moq_net::{Timestamp, track};

use crate::Shape;
use crate::object;
use crate::stats::Stats;

/// Produce frames on one track until the process exits.
///
/// Each group opens with the keyframe describing the shape, then carries
/// `group_size` zeroed frames. The loop never returns: a track that stopped
/// producing should still stay published, and the caller holds it open instead.
pub async fn produce(
    shape: Shape,
    mut track: track::Producer,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    // An idle track stays published without producing, which is how a run isolates
    // the control plane. Returning a pending future avoids a division by zero below.
    if shape.fps == 0 {
        return std::future::pending::<anyhow::Result<()>>().await;
    }

    // Both frames are fixed for the track, so every group clones them by reference
    // and the loop does no encoding or allocation of its own.
    let keyframe = object::encode(&shape);
    let zeros = Bytes::from(vec![0u8; shape.frame_size as usize]);
    let period = Duration::from_secs_f64(1.0 / shape.fps as f64);
    let mut ticker = tokio::time::interval(period);
    // A stalled tick delays the next frame rather than queueing a burst to catch up,
    // so a scheduling hiccup cannot inflate the offered load.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // The group opens only once its keyframe is due. Opening it before the tick
        // would hold an empty group, and possibly its stream, open for a whole period,
        // which inflates every lifecycle measured from the group's creation.
        ticker.tick().await;
        let mut group = track.append_group()?;
        stats.frame_sent(keyframe.len());
        group.write_frame(Timestamp::now(), keyframe.clone())?;

        for _ in 0..shape.group_size {
            ticker.tick().await;
            stats.frame_sent(zeros.len());
            group.write_frame(Timestamp::now(), zeros.clone())?;
        }

        group.finish()?;
    }
}
