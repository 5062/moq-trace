//! Counters shared by a peer's publisher and subscriber tasks.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Frame, byte, and group counters shared across a peer's tasks.
#[derive(Default)]
pub struct Stats {
    connections: AtomicU64,
    frames_sent: AtomicU64,
    bytes_sent: AtomicU64,
    groups_sent: AtomicU64,
    frames_recv: AtomicU64,
    bytes_recv: AtomicU64,
    groups_recv: AtomicU64,
    subscriptions: AtomicU64,
    mismatches: AtomicU64,
}

/// A point-in-time copy of the counters, used to compute interval rates.
#[derive(Clone, Copy, Default)]
struct Counters {
    frames_sent: u64,
    bytes_sent: u64,
    frames_recv: u64,
    bytes_recv: u64,
    groups_recv: u64,
    mismatches: u64,
}

impl Stats {
    /// Count a session as live until the returned guard drops.
    ///
    /// The reporter logs this as `connections`, which is the counter a runner waits
    /// on before it starts measuring: a peer that has not finished connecting would
    /// publish an empty trace.
    pub fn connection(&self) -> Gauge<'_> {
        self.connections.fetch_add(1, Ordering::Relaxed);
        Gauge(&self.connections)
    }

    /// Record one emitted frame of `bytes` bytes.
    pub fn frame_sent(&self, bytes: usize) {
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record one started group.
    pub fn group_sent(&self) {
        self.groups_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one received frame of `bytes` bytes.
    pub fn frame_recv(&self, bytes: usize) {
        self.frames_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record one received group.
    pub fn group_recv(&self) {
        self.groups_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a frame whose length disagrees with the size its keyframe declared,
    /// which means the object was truncated or re-framed somewhere on the path.
    pub fn mismatch(&self) {
        self.mismatches.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a subscription as live until the returned guard drops.
    pub fn subscription(&self) -> Gauge<'_> {
        self.subscriptions.fetch_add(1, Ordering::Relaxed);
        Gauge(&self.subscriptions)
    }

    /// Log a counter line every `interval` until the task is dropped.
    pub async fn report(self: Arc<Self>, interval: Duration) {
        let mut previous = self.counters();
        let mut last = Instant::now();

        loop {
            tokio::time::sleep(interval).await;

            let elapsed = last.elapsed().as_secs_f64();
            last = Instant::now();
            let current = self.counters();
            let sent = (current.frames_sent - previous.frames_sent) as f64 / elapsed;
            let recv = (current.frames_recv - previous.frames_recv) as f64 / elapsed;
            let send_mbps = (current.bytes_sent - previous.bytes_sent) as f64 * 8.0 / elapsed / 1e6;
            let recv_mbps = (current.bytes_recv - previous.bytes_recv) as f64 * 8.0 / elapsed / 1e6;
            let mismatches = current.mismatches - previous.mismatches;
            previous = current;

            tracing::info!(
                connections = self.connections.load(Ordering::Relaxed),
                subscriptions = self.subscriptions.load(Ordering::Relaxed),
                send_fps = format!("{sent:.1}"),
                recv_fps = format!("{recv:.1}"),
                send_mbps = format!("{send_mbps:.2}"),
                recv_mbps = format!("{recv_mbps:.2}"),
                groups_recv = current.groups_recv,
                mismatches,
                "stats"
            );
        }
    }

    fn counters(&self) -> Counters {
        Counters {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            frames_recv: self.frames_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            groups_recv: self.groups_recv.load(Ordering::Relaxed),
            mismatches: self.mismatches.load(Ordering::Relaxed),
        }
    }
}

/// A live count. Drops the counter it was created for when the session or
/// subscription ends, including when its task is aborted, so the reported gauge
/// tracks reality rather than attempts.
pub struct Gauge<'a>(&'a AtomicU64);

impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The connection gauge counts live sessions. A runner gates on `connections=N`
    /// before starting its window, so a session that already left must not hold the
    /// count up.
    #[test]
    fn connection_gauge_tracks_live_sessions() {
        let stats = Stats::default();
        let first = stats.connection();
        let second = stats.connection();
        assert_eq!(stats.connections.load(Ordering::Relaxed), 2);

        drop(first);
        assert_eq!(stats.connections.load(Ordering::Relaxed), 1);

        drop(second);
        assert_eq!(stats.connections.load(Ordering::Relaxed), 0);
    }
}
