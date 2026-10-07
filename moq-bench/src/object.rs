//! The synthetic object shape both peers publish and verify.

use moq_net::bytes::{BufMut, Bytes, BytesMut};

use crate::Shape;

/// The single track name every bench broadcast publishes.
pub const TRACK: &str = "data";

/// Marks the first frame of a group as a bench keyframe.
const MAGIC: [u8; 8] = *b"moqbench";

/// Bytes of keyframe header: the magic, then `frame_size`, `group_size`, and `fps`
/// as little-endian `u64`s.
///
/// `--frame-size` must be at least this long, so every frame of a group can be
/// exactly one size.
pub const HEADER_LEN: usize = MAGIC.len() + 3 * size_of::<u64>();

/// Encode the keyframe that opens every group of a track, zero-padded to `frame_size`.
///
/// The keyframe carries only the shape, which is fixed for a track, so a publisher
/// encodes it once and every group shares the same buffer. Group sequence, path,
/// and timing are already on the wire or in the trace and are not repeated here.
///
/// # Panics
///
/// If `shape.frame_size` is shorter than [`HEADER_LEN`], which argument parsing
/// rejects.
#[must_use]
pub fn encode(shape: &Shape) -> Bytes {
    let size = usize::try_from(shape.frame_size).expect("frame size fits in memory");
    assert!(
        size >= HEADER_LEN,
        "frame size {size} is shorter than the keyframe header"
    );

    let mut bytes = BytesMut::with_capacity(size);
    bytes.put_slice(&MAGIC);
    bytes.put_u64_le(shape.frame_size);
    bytes.put_u64_le(shape.group_size);
    bytes.put_u64_le(shape.fps);
    bytes.resize(size, 0);
    bytes.freeze()
}

/// Read the shape back from a group's first frame, ignoring the padding.
///
/// Returns `None` when the frame does not start with a keyframe header, which is
/// what a subscriber sees when its first group arrived without its opening frames.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<Shape> {
    let header = payload.get(..HEADER_LEN)?;
    let (magic, fields) = header.split_at(MAGIC.len());
    if magic != MAGIC {
        return None;
    }
    let field = |index: usize| {
        let start = index * size_of::<u64>();
        let bytes = fields[start..start + size_of::<u64>()]
            .try_into()
            .expect("an eight-byte slice");
        u64::from_le_bytes(bytes)
    };
    Some(Shape {
        frame_size: field(0),
        group_size: field(1),
        fps: field(2),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> Shape {
        Shape {
            fps: 30,
            frame_size: 512,
            group_size: 4,
        }
    }

    #[test]
    fn pads_to_frame_size() {
        assert_eq!(encode(&shape()).len(), 512);
    }

    #[test]
    fn round_trips_through_padding() {
        let decoded = decode(&encode(&shape())).unwrap();
        assert_eq!(decoded.fps, 30);
        assert_eq!(decoded.frame_size, 512);
        assert_eq!(decoded.group_size, 4);
    }

    #[test]
    fn fits_exactly_at_header_length() {
        let shape = Shape {
            frame_size: HEADER_LEN as u64,
            ..shape()
        };
        assert_eq!(
            decode(&encode(&shape)).unwrap().frame_size,
            HEADER_LEN as u64
        );
    }

    /// A zeroed frame, the one a group that lost its keyframe starts with, is not
    /// mistaken for a header.
    #[test]
    fn rejects_frames_without_a_header() {
        assert!(decode(&[0; 512]).is_none());
        assert!(decode(&MAGIC).is_none());
    }
}
