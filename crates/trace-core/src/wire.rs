//! Encoding rules the MoQ and QUIC provider payloads share.

/// Whether a phase record starts or completes work.
///
/// A provider binding casts this to its wire value, so the declaration order is
/// the encoding and must match the `*_EDGE_*` C enum of every provider.
/// Reordering the variants changes the wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseEdge {
    /// The phase started.
    Start,
    /// The phase completed.
    Done,
}

/// Encode an optional field as its presence flag and wire value.
///
/// A provider payload has no sum type for an absent field, so the `has_` flag
/// and a zero value together carry the option.
pub fn encode_optional<T: Copy + Default>(value: Option<T>) -> (u8, T) {
    value.map_or((0, T::default()), |value| (1, value))
}
