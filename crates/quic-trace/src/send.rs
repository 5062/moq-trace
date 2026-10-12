use crate::{PacketOutcome, PacketPhase, PacketPhaseTrace, PacketTrace};

/// The TX packets one send carries, waiting until that send returns.
///
/// A TX packet's lifecycle ends when the send system call that accepts its
/// datagram returns, so each packet waits in its `send_queue` phase from the
/// end of encryption until then. A stack adds each packet as it finishes
/// encrypting, moves the batch along with the bytes through any coalescing or
/// write-blocked queue, and ends every packet at the send's completion.
///
/// Dropping the batch records every packet still in it as abandoned: one that
/// was never sent, or one handed to a writer that sends it later without
/// saying when.
#[derive(Default)]
#[must_use = "dropping a pending send records its packets as abandoned"]
pub struct PendingSend(Vec<(PacketTrace, PacketPhaseTrace)>);

impl PendingSend {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold a packet whose encryption just ended, starting its `send_queue` phase.
    ///
    /// A disabled packet is not held, so a batch of untraced packets stays empty.
    pub fn push(&mut self, packet: PacketTrace) {
        if !packet.is_traced() {
            return;
        }
        let queue = packet.phase(PacketPhase::SendQueue);
        self.0.push((packet, queue));
    }

    /// Take every packet of `other`, as when packets coalesce into one datagram.
    pub fn append(&mut self, other: &mut PendingSend) {
        self.0.append(&mut other.0);
    }

    /// Return whether the batch holds no traced packet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// End every packet at `at_ns`, when the send that accepted them returned.
    pub fn sent(self, at_ns: u64) {
        self.finish_at(PacketOutcome::Success, at_ns);
    }

    /// End every packet as dropped at `at_ns`, when the send that failed returned.
    ///
    /// A send the kernel rejected never put the packets on the wire, whatever
    /// the stack then does with the error.
    pub fn dropped(self, at_ns: u64) {
        self.finish_at(PacketOutcome::Dropped, at_ns);
    }

    /// End every packet, and its `send_queue` phase, with `outcome` at `at_ns`.
    pub fn finish_at(self, outcome: PacketOutcome, at_ns: u64) {
        for (packet, queue) in self.0 {
            queue.finish_at(outcome, at_ns);
            packet.finish_at(outcome, at_ns);
        }
    }
}
