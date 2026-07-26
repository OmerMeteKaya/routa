//! HTTP/2 frame header parsing and serialization (RFC 9113 4.1).
//! Every frame on the wire starts with a fixed 9-byte header (24-bit
//! length, 8-bit type, 8-bit flags, 32-bit stream id with the
//! reserved top bit masked off) followed by exactly `length` bytes of
//! type-specific payload -- this module only handles that header plus
//! enough structure to hand the right payload bytes to whichever
//! frame-specific parser needs them. Per-frame-type payload
//! interpretation (SETTINGS parameters, HEADERS field blocks via
//! HPACK, etc.) lives in `stream`/`hpack`, not here.

pub const FRAME_HEADER_LEN: usize = 9;

/// The maximum frame length any implementation is required to accept
/// without prior SETTINGS negotiation (RFC 9113 4.2) -- 2^14. A larger
/// value can be advertised/accepted only after both sides have agreed
/// to it via `SETTINGS_MAX_FRAME_SIZE`.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The absolute upper bound the 24-bit length field can represent
/// (2^24 - 1) -- SETTINGS_MAX_FRAME_SIZE can never validly exceed
/// this, regardless of what a peer advertises.
pub const ABSOLUTE_MAX_FRAME_SIZE: u32 = (1 << 24) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    /// Any type value not in RFC 9113's registry. Per 4.1, unknown
    /// frame types must be ignored (not treated as a connection
    /// error) -- carrying the raw byte through lets a caller do
    /// exactly that rather than this module deciding on their behalf.
    Unknown(u8),
}

impl FrameType {
    fn from_byte(b: u8) -> FrameType {
        match b {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            other => FrameType::Unknown(other),
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::Unknown(b) => b,
        }
    }
}

// ─── Common frame flags (RFC 9113 4.1; meaning is frame-type-specific,
// but the bit positions below are the ones actually used across the
// types this module's callers care about) ──────────────────────────

pub const FLAG_END_STREAM: u8 = 0x1; // DATA, HEADERS
pub const FLAG_ACK: u8 = 0x1; // SETTINGS, PING (same bit, different frame type)
pub const FLAG_END_HEADERS: u8 = 0x4; // HEADERS, PUSH_PROMISE, CONTINUATION
pub const FLAG_PADDED: u8 = 0x8; // DATA, HEADERS, PUSH_PROMISE
pub const FLAG_PRIORITY: u8 = 0x20; // HEADERS

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub length: u32, // 24-bit on the wire, stored widened for convenience
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32, // top (reserved) bit always masked off
}

impl FrameHeader {
    /// Parses the fixed 9-byte frame header from the start of `data`.
    /// Returns `None` if fewer than `FRAME_HEADER_LEN` bytes are
    /// available -- callers treat that as "need more data", not a
    /// parse error, since a frame header can legitimately arrive split
    /// across TCP reads.
    pub fn parse(data: &[u8]) -> Option<FrameHeader> {
        if data.len() < FRAME_HEADER_LEN {
            return None;
        }
        let length = (u32::from(data[0]) << 16) | (u32::from(data[1]) << 8) | u32::from(data[2]);
        let frame_type = FrameType::from_byte(data[3]);
        let flags = data[4];
        let stream_id = ((u32::from(data[5]) & 0x7f) << 24)
            | (u32::from(data[6]) << 16)
            | (u32::from(data[7]) << 8)
            | u32::from(data[8]);
        Some(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push((self.length >> 16) as u8);
        out.push((self.length >> 8) as u8);
        out.push(self.length as u8);
        out.push(self.frame_type.to_byte());
        out.push(self.flags);
        out.push((self.stream_id >> 24) as u8 & 0x7f); // reserved bit stays 0
        out.push((self.stream_id >> 16) as u8);
        out.push((self.stream_id >> 8) as u8);
        out.push(self.stream_id as u8);
    }
}

/// A frame's header plus a borrowed view of its payload from whatever
/// buffer it was parsed out of. Doesn't own or copy the payload --
/// callers that need to keep it past the buffer's next mutation (a
/// HEADERS payload accumulating across CONTINUATION frames, for
/// instance) copy out what they need themselves.
pub struct Frame<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
}

/// Attempts to parse one complete frame (header + payload) from the
/// start of `data`. Returns the frame and how many bytes it occupied,
/// or `None` if `data` doesn't yet contain a complete frame -- exactly
/// analogous to `http::request::parse`'s `Incomplete` case, but
/// expressed as `Option` here since a frame parse has no notion of a
/// malformed-vs-incomplete distinction at this layer (an oversized
/// `length` is caught by the caller checking it against the
/// negotiated max frame size, not by this function).
pub fn parse_frame(data: &[u8]) -> Option<(Frame<'_>, usize)> {
    let header = FrameHeader::parse(data)?;
    let total_len = FRAME_HEADER_LEN + header.length as usize;
    if data.len() < total_len {
        return None;
    }
    let payload = &data[FRAME_HEADER_LEN..total_len];
    Some((Frame { header, payload }, total_len))
}

// ─── Frame serialization helpers ────────────────────────────────────────
//
// Each of these appends a complete frame (header + payload) to `out`.
// Kept as free functions taking the specific fields each frame type
// needs, rather than a single "build any frame" function, so a call
// site can't accidentally supply fields that don't apply to the frame
// type it's building.

#[derive(Debug, Clone, Copy)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

pub fn write_settings(out: &mut Vec<u8>, settings: &[Setting]) {
    let header = FrameHeader {
        length: (settings.len() * 6) as u32,
        frame_type: FrameType::Settings,
        flags: 0,
        stream_id: 0,
    };
    header.write(out);
    for s in settings {
        out.push((s.id >> 8) as u8);
        out.push(s.id as u8);
        out.push((s.value >> 24) as u8);
        out.push((s.value >> 16) as u8);
        out.push((s.value >> 8) as u8);
        out.push(s.value as u8);
    }
}

pub fn write_settings_ack(out: &mut Vec<u8>) {
    let header = FrameHeader {
        length: 0,
        frame_type: FrameType::Settings,
        flags: FLAG_ACK,
        stream_id: 0,
    };
    header.write(out);
}

pub fn write_goaway(out: &mut Vec<u8>, last_stream_id: u32, error_code: u32) {
    let header = FrameHeader {
        length: 8,
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: 0,
    };
    header.write(out);
    out.push((last_stream_id >> 24) as u8 & 0x7f);
    out.push((last_stream_id >> 16) as u8);
    out.push((last_stream_id >> 8) as u8);
    out.push(last_stream_id as u8);
    out.extend_from_slice(&error_code.to_be_bytes());
}

pub fn write_rst_stream(out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::RstStream,
        flags: 0,
        stream_id,
    };
    header.write(out);
    out.extend_from_slice(&error_code.to_be_bytes());
}

pub fn write_window_update(out: &mut Vec<u8>, stream_id: u32, increment: u32) {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::WindowUpdate,
        flags: 0,
        stream_id,
    };
    header.write(out);
    out.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
}

pub fn write_ping(out: &mut Vec<u8>, payload: &[u8; 8], ack: bool) {
    let header = FrameHeader {
        length: 8,
        frame_type: FrameType::Ping,
        flags: if ack { FLAG_ACK } else { 0 },
        stream_id: 0,
    };
    header.write(out);
    out.extend_from_slice(payload);
}

/// Writes a DATA frame. `end_stream` sets `FLAG_END_STREAM`; padding
/// isn't supported for outbound frames (routa never pads its own
/// responses -- see this module's parent doc comment on padding's
/// purpose being a client-side timing-attack mitigation, not something
/// a server benefits from generating).
pub fn write_data(out: &mut Vec<u8>, stream_id: u32, data: &[u8], end_stream: bool) {
    let header = FrameHeader {
        length: data.len() as u32,
        frame_type: FrameType::Data,
        flags: if end_stream { FLAG_END_STREAM } else { 0 },
        stream_id,
    };
    header.write(out);
    out.extend_from_slice(data);
}

/// Writes a HEADERS frame from an already-HPACK-encoded field block
/// (see `hpack::encode`). `end_stream` sets `FLAG_END_STREAM`;
/// `end_headers` sets `FLAG_END_HEADERS` -- callers that need to split
/// a field block across HEADERS + CONTINUATION frames (larger than one
/// frame's negotiated max size) pass `end_headers: false` here and
/// follow up with `write_continuation` for the remainder.
pub fn write_headers(
    out: &mut Vec<u8>,
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
    end_headers: bool,
) {
    let mut flags = 0u8;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if end_headers {
        flags |= FLAG_END_HEADERS;
    }
    let header = FrameHeader {
        length: header_block.len() as u32,
        frame_type: FrameType::Headers,
        flags,
        stream_id,
    };
    header.write(out);
    out.extend_from_slice(header_block);
}

pub fn write_continuation(out: &mut Vec<u8>, stream_id: u32, header_block: &[u8], end_headers: bool) {
    let header = FrameHeader {
        length: header_block.len() as u32,
        frame_type: FrameType::Continuation,
        flags: if end_headers { FLAG_END_HEADERS } else { 0 },
        stream_id,
    };
    header.write(out);
    out.extend_from_slice(header_block);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trips() {
        let header = FrameHeader {
            length: 1234,
            frame_type: FrameType::Headers,
            flags: FLAG_END_HEADERS | FLAG_END_STREAM,
            stream_id: 0x0102_0304 & 0x7fff_ffff,
        };
        let mut buf = Vec::new();
        header.write(&mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_LEN);

        let parsed = FrameHeader::parse(&buf).unwrap();
        assert_eq!(parsed.length, 1234);
        assert_eq!(parsed.frame_type, FrameType::Headers);
        assert_eq!(parsed.flags, FLAG_END_HEADERS | FLAG_END_STREAM);
        assert_eq!(parsed.stream_id, header.stream_id);
    }

    #[test]
    fn reserved_bit_is_masked_off_on_parse() {
        // Manually craft a header with the reserved top bit set to 1
        // -- RFC 9113 4.1 requires it to be ignored on receipt, not
        // treated as part of the stream id.
        let mut buf = vec![0u8; FRAME_HEADER_LEN];
        buf[5] = 0xff; // top bit set + some stream-id bits
        buf[6] = 0x00;
        buf[7] = 0x00;
        buf[8] = 0x01;
        let parsed = FrameHeader::parse(&buf).unwrap();
        assert_eq!(parsed.stream_id, 0x7f00_0001);
    }

    #[test]
    fn incomplete_header_returns_none() {
        let buf = vec![0u8; FRAME_HEADER_LEN - 1];
        assert!(FrameHeader::parse(&buf).is_none());
    }

    #[test]
    fn unknown_frame_type_preserved_not_rejected() {
        let mut buf = vec![0u8; FRAME_HEADER_LEN];
        buf[3] = 0xEE; // not in RFC 9113's registry
        let parsed = FrameHeader::parse(&buf).unwrap();
        assert_eq!(parsed.frame_type, FrameType::Unknown(0xEE));
    }

    #[test]
    fn parse_frame_returns_none_when_payload_incomplete() {
        let mut buf = Vec::new();
        let header = FrameHeader {
            length: 10,
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
        };
        header.write(&mut buf);
        buf.extend_from_slice(&[0u8; 5]); // only 5 of the promised 10 bytes
        assert!(parse_frame(&buf).is_none());
    }

    #[test]
    fn parse_frame_succeeds_with_complete_payload() {
        let mut buf = Vec::new();
        write_data(&mut buf, 1, b"hello", true);
        let (frame, consumed) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert_eq!(frame.header.flags, FLAG_END_STREAM);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_frame_leaves_trailing_bytes_unconsumed() {
        let mut buf = Vec::new();
        write_data(&mut buf, 1, b"hello", false);
        buf.extend_from_slice(b"next frame starts here");
        let (_frame, consumed) = parse_frame(&buf).unwrap();
        assert_eq!(consumed, FRAME_HEADER_LEN + 5); // just the DATA frame itself
    }

    // ─── Serialization helpers ──────────────────────────────────────

    #[test]
    fn write_settings_encodes_all_pairs() {
        let mut buf = Vec::new();
        write_settings(
            &mut buf,
            &[
                Setting { id: 0x1, value: 4096 },
                Setting { id: 0x3, value: 100 },
            ],
        );
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Settings);
        assert_eq!(frame.header.length, 12); // 2 settings * 6 bytes
        assert_eq!(frame.payload.len(), 12);
    }

    #[test]
    fn write_settings_ack_has_ack_flag_and_no_payload() {
        let mut buf = Vec::new();
        write_settings_ack(&mut buf);
        let (frame, consumed) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.flags, FLAG_ACK);
        assert_eq!(frame.header.length, 0);
        assert_eq!(consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn write_goaway_encodes_last_stream_id_and_error_code() {
        let mut buf = Vec::new();
        write_goaway(&mut buf, 7, 1);
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::GoAway);
        assert_eq!(&frame.payload[0..4], &[0, 0, 0, 7]);
        assert_eq!(&frame.payload[4..8], &[0, 0, 0, 1]);
    }

    #[test]
    fn write_rst_stream_encodes_stream_id_and_error_code() {
        let mut buf = Vec::new();
        write_rst_stream(&mut buf, 3, 8); // CANCEL = 8
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::RstStream);
        assert_eq!(frame.header.stream_id, 3);
        assert_eq!(&frame.payload[..], &[0, 0, 0, 8]);
    }

    #[test]
    fn write_window_update_masks_reserved_bit() {
        let mut buf = Vec::new();
        write_window_update(&mut buf, 5, 0xffff_ffff); // top bit should be masked
        let (frame, _) = parse_frame(&buf).unwrap();
        let increment = u32::from_be_bytes(frame.payload.try_into().unwrap());
        assert_eq!(increment, 0x7fff_ffff);
    }

    #[test]
    fn write_ping_round_trips_payload() {
        let mut buf = Vec::new();
        let payload = *b"abcdefgh";
        write_ping(&mut buf, &payload, false);
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Ping);
        assert_eq!(frame.header.flags, 0);
        assert_eq!(frame.payload, &payload);
    }

    #[test]
    fn write_ping_ack_sets_ack_flag() {
        let mut buf = Vec::new();
        write_ping(&mut buf, &[0u8; 8], true);
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.flags, FLAG_ACK);
    }

    #[test]
    fn write_headers_sets_requested_flags() {
        let mut buf = Vec::new();
        write_headers(&mut buf, 1, b"encoded-block", true, true);
        let (frame, _) = parse_frame(&buf).unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Headers);
        assert_eq!(frame.header.flags, FLAG_END_STREAM | FLAG_END_HEADERS);
        assert_eq!(frame.payload, b"encoded-block");
    }

    #[test]
    fn write_headers_without_end_headers_allows_continuation() {
        let mut buf = Vec::new();
        write_headers(&mut buf, 1, b"part1", false, false);
        write_continuation(&mut buf, 1, b"part2", true);

        let (first, consumed1) = parse_frame(&buf).unwrap();
        assert_eq!(first.header.frame_type, FrameType::Headers);
        assert_eq!(first.header.flags & FLAG_END_HEADERS, 0);

        let (second, _) = parse_frame(&buf[consumed1..]).unwrap();
        assert_eq!(second.header.frame_type, FrameType::Continuation);
        assert_eq!(second.header.flags, FLAG_END_HEADERS);
        assert_eq!(second.payload, b"part2");
    }
}
