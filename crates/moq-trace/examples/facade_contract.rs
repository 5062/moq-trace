//! Emit the same lifecycle fixture as cpp/tests/facade_contract.cpp.
//!
//! The native capture check compares payloads across both facades, including
//! optional metadata, explicit completion, and abandonment on scope exit.

use moq_trace::{
    ConnectionPath, Direction, LogicalId, ObjectContext, ObjectIdentity, ObjectOutcome,
    ObjectPhase, PacketContext, PacketOutcome, PacketPhase, PacketSpace, SendBlockedReason,
    SocketOutcome, SocketStats, StreamFrame,
};

fn main() {
    let handle = moq_trace::global();
    let connection = moq_trace::next_connection_id();
    let session = moq_trace::next_session_id();
    let logical = moq_trace::next_logical_id();
    handle.connection_path(
        connection,
        ConnectionPath::new(
            "10.0.0.1:4443".parse().unwrap(),
            "[2001:db8::2]:50000".parse().unwrap(),
        ),
    );
    for direction in [Direction::Rx, Direction::Tx] {
        let object_handle = handle
            .clone()
            .with_session_id(session)
            .with_connection_id(connection);
        let mut object = object_handle.object(
            ObjectContext::new(direction, ObjectIdentity::new(3, 4, 5), logical)
                .with_stream_id(7)
                .with_stream_offset_start(8)
                .with_start_ns(100),
        );
        for phase in [
            ObjectPhase::HeaderParse,
            ObjectPhase::Create,
            ObjectPhase::PayloadRead,
            ObjectPhase::FrameCommit,
            ObjectPhase::Clone,
            ObjectPhase::HeaderEncode,
            ObjectPhase::PayloadWrite,
            ObjectPhase::Notify,
            ObjectPhase::DeliveryWait,
            ObjectPhase::WriteBlocked,
            ObjectPhase::TransportCall,
        ] {
            object.phase(phase).finish(ObjectOutcome::Success);
        }
        object
            .phase_at(ObjectPhase::DeliveryWait, 50)
            .finish_at(ObjectOutcome::Success, 150);
        object.set_payload_bytes(1024);
        object.set_stream_offset_end(1032);
        object.finish(ObjectOutcome::Success);
        let mut abandoned = handle.object(ObjectContext::new(
            direction,
            ObjectIdentity::new(0, 0, 0),
            LogicalId::new(0, 0),
        ));
        drop(abandoned.phase(ObjectPhase::Create));
        drop(abandoned);
        let mut failed = handle.object(ObjectContext::new(
            direction,
            ObjectIdentity::new(0, 0, 0),
            LogicalId::new(0, 0),
        ));
        failed
            .phase(ObjectPhase::PayloadWrite)
            .finish(ObjectOutcome::Failed);
        failed.finish(ObjectOutcome::Failed);
        for space in [
            PacketSpace::Initial,
            PacketSpace::Handshake,
            PacketSpace::ZeroRtt,
            PacketSpace::Data,
        ] {
            let packet = handle.packet(
                PacketContext::new(direction, connection)
                    .with_number(9)
                    .with_space(space)
                    .with_byte_len(1200)
                    .with_start_ns(200),
            );
            for phase in [
                PacketPhase::HeaderParse,
                PacketPhase::Routing,
                PacketPhase::Scheduling,
                PacketPhase::HeaderUnprotect,
                PacketPhase::PayloadDecrypt,
                PacketPhase::FrameProcess,
                PacketPhase::FrameEncode,
                PacketPhase::PacketEncrypt,
                PacketPhase::Application,
                PacketPhase::ReadQueue,
                PacketPhase::SendQueue,
            ] {
                packet.phase(phase).finish(PacketOutcome::Success);
            }
            packet.stream_frame(StreamFrame::new(7, 8, 1032), PacketOutcome::Success);
            for retransmission in [false, true] {
                packet.stream_frame(
                    StreamFrame::new(7, 8, 1032).with_retransmission(retransmission),
                    PacketOutcome::Success,
                );
            }
            packet.finish(PacketOutcome::Success);
        }
        let mut completed =
            handle.packet(PacketContext::new(direction, connection).with_start_ns(250));
        completed.set_number(10);
        completed.set_space(PacketSpace::Data);
        completed.set_byte_len(1200);
        completed
            .phase_at(PacketPhase::SendQueue, 300)
            .finish_at(PacketOutcome::Success, 400);
        completed.stream_frame_at(StreamFrame::new(7, 8, 1032), PacketOutcome::Success, 450);
        completed.finish_at(PacketOutcome::Success, 500);
        handle.socket(direction, Some(connection)).finish_at(
            SocketOutcome::Success,
            SocketStats::new(1, 2, 1200),
            600,
        );
        for outcome in [
            PacketOutcome::Malformed,
            PacketOutcome::AuthenticationFailed,
            PacketOutcome::Dropped,
        ] {
            let packet = handle.packet(PacketContext::new(direction, connection));
            packet.phase(PacketPhase::FrameProcess).finish(outcome);
            packet.stream_frame(StreamFrame::new(7, 8, 1032), outcome);
            packet.finish(outcome);
        }
        let abandoned = handle.packet(PacketContext::new(direction, connection));
        drop(abandoned.phase(PacketPhase::FrameProcess));
        drop(abandoned);
        for outcome in [
            SocketOutcome::Success,
            SocketOutcome::Pending,
            SocketOutcome::WouldBlock,
            SocketOutcome::ConnectionReset,
            SocketOutcome::Error,
        ] {
            handle
                .socket(direction, Some(connection))
                .finish(outcome, SocketStats::new(1, 2, 1200));
        }
        drop(handle.socket(direction, None));
    }
    for reason in [
        SendBlockedReason::CongestionWindow,
        SendBlockedReason::Pacing,
        SendBlockedReason::Amplification,
        SendBlockedReason::ConnectionFlowControl,
        SendBlockedReason::StreamFlowControl,
        SendBlockedReason::SendBuffer,
    ] {
        handle.send_blocked(connection, reason, None).finish();
        drop(handle.send_blocked(connection, reason, Some(7)));
    }
}
