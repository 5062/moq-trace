//! The synthetic object shape both peers publish and verify.

use moq_net::bytes::Bytes;
use serde::{Deserialize, Serialize};

/// The single track name every bench broadcast publishes.
pub const TRACK: &str = "data";

/// The JSON keyframe that opens every group.
///
/// A subscriber reads it back to learn the shape of a broadcast it did not
/// publish, so nothing has to be passed between the peers out of band.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Header {
    /// Broadcast path the group was published under.
    pub broadcast: String,
    /// Group sequence number.
    pub group: u64,
    /// Frames per second the publisher emits.
    pub fps: u64,
    /// Size of every frame in the group, in bytes.
    pub frame_size: u64,
    /// Zeroed frames that follow the keyframe in each group.
    pub group_size: u64,
    /// Wall-clock milliseconds at emission, for rough one-way latency when the
    /// peers' clocks agree.
    pub timestamp_ms: u128,
}

impl Header {
    /// Encode the keyframe, padded to `frame_size`.
    ///
    /// A serialized header is smaller than most configured sizes, and padding it
    /// keeps every object in the group exactly one size, which is what makes object
    /// size a usable independent variable. Padding is never applied in reverse: a
    /// header larger than `frame_size` is returned whole rather than truncated, so a
    /// too-small size shows up as an oversized frame instead of a decode error.
    pub fn encode(&self, frame_size: u64) -> anyhow::Result<Bytes> {
        let mut bytes = serde_json::to_vec(self)?;
        if bytes.len() < frame_size as usize {
            bytes.resize(frame_size as usize, b' ');
        }
        Ok(Bytes::from(bytes))
    }

    /// Decode a keyframe, ignoring any padding.
    pub fn decode(payload: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(payload)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            broadcast: "bench/run/0".to_string(),
            group: 7,
            fps: 30,
            frame_size: 512,
            group_size: 4,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn pads_to_frame_size() {
        let encoded = header().encode(512).unwrap();
        assert_eq!(encoded.len(), 512);
    }

    #[test]
    fn round_trips_through_padding() {
        let decoded = Header::decode(&header().encode(512).unwrap()).unwrap();
        assert_eq!(decoded.group, 7);
        assert_eq!(decoded.frame_size, 512);
    }

    #[test]
    fn never_truncates_an_oversized_header() {
        let encoded = header().encode(8).unwrap();
        assert!(encoded.len() > 8);
        assert_eq!(Header::decode(&encoded).unwrap().group, 7);
    }
}
