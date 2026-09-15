//! Synthetic group consumption.

use std::sync::Arc;

use moq_net::broadcast;

use crate::object::{Header, TRACK};
use crate::stats::Stats;

/// Subscribe to a broadcast's track and drain it until the broadcast closes.
///
/// Every frame is counted by size. The keyframe of each group is parsed back and
/// its declared `frame_size` is checked against the frame that carried it, which
/// catches truncation or re-framing anywhere on the path without needing to know
/// how the publisher was configured.
pub async fn drain(broadcast: broadcast::Consumer, stats: Arc<Stats>) -> anyhow::Result<()> {
    let mut track = broadcast.track(TRACK)?.subscribe(None).await?;
    let _live = stats.subscription();

    while let Some(mut group) = track.recv_group().await? {
        let mut first = true;
        while let Some(frame) = group.read_frame().await? {
            if first {
                first = false;
                if let Ok(header) = Header::decode(&frame.payload) {
                    if frame.payload.len() != header.frame_size as usize {
                        stats.mismatch();
                    }
                } else {
                    tracing::warn!("unreadable keyframe");
                }
            }
            stats.frame_recv(frame.payload.len());
        }
        stats.group_recv();
    }
    Ok(())
}
