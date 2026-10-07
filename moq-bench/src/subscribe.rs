//! Synthetic group consumption.

use std::sync::Arc;

use moq_net::broadcast;

use crate::object::{self, TRACK};
use crate::stats::Stats;

/// Subscribe to a broadcast's track and drain it until the broadcast closes.
///
/// Every frame is counted by size. The keyframe of each group declares the shape,
/// and every frame of the group is checked against it, which catches truncation or
/// re-framing anywhere on the path without needing to know how the publisher was
/// configured.
pub async fn drain(broadcast: broadcast::Consumer, stats: Arc<Stats>) -> anyhow::Result<()> {
    let mut track = broadcast.track(TRACK)?.subscribe(None).await?;
    let _live = stats.subscription();

    while let Some(mut group) = track.recv_group().await? {
        let mut shape = None;
        let mut frames: u64 = 0;
        let mut mismatched = false;

        while let Some(frame) = group.read_frame().await? {
            let len = frame.payload.len() as u64;
            if frames == 0 {
                shape = object::decode(&frame.payload);
            }
            if shape.is_some_and(|shape| len != shape.frame_size) {
                mismatched = true;
            }
            frames += 1;
            stats.frame_recv(frame.payload.len());
        }

        // A group that never showed a keyframe lost its opening frames, which a relay
        // can do by joining a group partway. A group with fewer frames than its
        // keyframe declared was cut short, by a relay dropping it or by teardown.
        // Neither is broken framing, so both count apart from `mismatches`, which is
        // kept for frames the path altered.
        match shape {
            None => stats.group_short(),
            Some(shape) if frames < shape.group_size + 1 => stats.group_short(),
            Some(shape) if frames > shape.group_size + 1 => mismatched = true,
            Some(_) => {}
        }
        if mismatched {
            stats.mismatch();
        }
        stats.group_recv();
    }
    Ok(())
}
