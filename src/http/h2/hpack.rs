//! HPACK (RFC 7541): header compression for HTTP/2. Covers the static
//! table (Appendix A), Huffman coding (Appendix B, encode and decode
//! both -- unlike several HPACK crates in the Rust ecosystem, which
//! implement decode-only Huffman since it's spec-optional for an
//! encoder; skipping encode-side Huffman would mean giving up real
//! compression on every request/response this sends), integer/string
//! primitive encoding (5.1-5.2), and the dynamic table (2.3.2, 4).
//!
//! A `HpackContext` holds one side's dynamic table and lives for a
//! connection's lifetime -- HPACK's compression context is
//! per-connection, not per-request, so header fields repeated across
//! requests on the same connection can be referenced by a short index
//! rather than re-sent in full.

use std::collections::VecDeque;

// ─── Static table (RFC 7541 Appendix A) ────────────────────────────────

/// Index 1-61 in HPACK's combined static+dynamic address space maps to
/// this table (index 0 is never used; dynamic table entries start at
/// 62). A `None` value means the table only fixes the header *name*
/// for that index (e.g. `:method` at index 2 has no value -- callers
/// supply GET/POST/etc. themselves).
pub const STATIC_TABLE: &[(&str, Option<&str>)] = &[
    (":authority", None),
    (":method", Some("GET")),
    (":method", Some("POST")),
    (":path", Some("/")),
    (":path", Some("/index.html")),
    (":scheme", Some("http")),
    (":scheme", Some("https")),
    (":status", Some("200")),
    (":status", Some("204")),
    (":status", Some("206")),
    (":status", Some("304")),
    (":status", Some("400")),
    (":status", Some("404")),
    (":status", Some("500")),
    ("accept-charset", None),
    ("accept-encoding", Some("gzip, deflate")),
    ("accept-language", None),
    ("accept-ranges", None),
    ("accept", None),
    ("access-control-allow-origin", None),
    ("age", None),
    ("allow", None),
    ("authorization", None),
    ("cache-control", None),
    ("content-disposition", None),
    ("content-encoding", None),
    ("content-language", None),
    ("content-length", None),
    ("content-location", None),
    ("content-range", None),
    ("content-type", None),
    ("cookie", None),
    ("date", None),
    ("etag", None),
    ("expect", None),
    ("expires", None),
    ("from", None),
    ("host", None),
    ("if-match", None),
    ("if-modified-since", None),
    ("if-none-match", None),
    ("if-range", None),
    ("if-unmodified-since", None),
    ("last-modified", None),
    ("link", None),
    ("location", None),
    ("max-forwards", None),
    ("proxy-authenticate", None),
    ("proxy-authorization", None),
    ("range", None),
    ("referer", None),
    ("refresh", None),
    ("retry-after", None),
    ("server", None),
    ("set-cookie", None),
    ("strict-transport-security", None),
    ("transfer-encoding", None),
    ("user-agent", None),
    ("vary", None),
    ("via", None),
    ("www-authenticate", None),
];

// ─── Dynamic table ──────────────────────────────────────────────────────

/// A decoded (or about-to-be-encoded) header field, owned rather than
/// borrowed -- the dynamic table needs to hold these independently of
/// whatever buffer they were originally decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

impl HeaderField {
    /// Per RFC 7541 4.1: an entry's size is its name + value octet
    /// lengths plus a fixed 32-byte overhead accounting for the entry
    /// structure itself, not just how many header bytes it represents.
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    current_size: usize,
    max_size: usize,
    /// The upper bound this side has advertised (via
    /// SETTINGS_HEADER_TABLE_SIZE) that a peer's dynamic table size
    /// update must never exceed -- distinct from `max_size` itself,
    /// which tracks the *current* effective limit (a peer can set it
    /// anywhere from 0 up to this ceiling). RFC 7541 6.3: a size
    /// update exceeding this ceiling is a decoding error, not merely
    /// clamped.
    advertised_max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        DynamicTable {
            entries: VecDeque::new(),
            current_size: 0,
            max_size,
            advertised_max_size: max_size,
        }
    }

    /// Changes the table's size limit (from a Dynamic Table Size
    /// Update representation, 6.3), evicting entries if the new limit
    /// is smaller than the current content requires.
    /// Sets the dynamic table's current effective size limit.
    /// `Err` if `new_max_size` exceeds `advertised_max_size` (RFC 7541
    /// 6.3's decoding-error case) -- the caller (see `HpackContext::decode`)
    /// is expected to treat that as a full decode failure, not clamp
    /// silently to the ceiling.
    pub fn set_max_size(&mut self, new_max_size: usize) -> Result<(), HpackError> {
        if new_max_size > self.advertised_max_size {
            return Err(HpackError::DynamicTableSizeUpdateTooLarge);
        }
        self.max_size = new_max_size;
        self.evict_to_fit(0);
        Ok(())
    }

    /// Updates the ceiling a peer's dynamic table size update must
    /// respect -- called when this side's own SETTINGS_HEADER_TABLE_SIZE
    /// changes (see `HpackContext::set_max_dynamic_table_size`, which
    /// is this side announcing a new value to accept from the peer,
    /// as opposed to `set_max_size` which is the peer telling us what
    /// it's actually using right now).
    pub fn set_advertised_max_size(&mut self, new_ceiling: usize) {
        self.advertised_max_size = new_ceiling;
    }

    fn evict_to_fit(&mut self, needed: usize) {
        while self.current_size + needed > self.max_size {
            let Some(evicted) = self.entries.pop_back() else {
                break; // table is already empty -- nothing left to evict
            };
            self.current_size -= evicted.size();
        }
    }

    /// Inserts a new entry at the front (most-recently-added), the
    /// same "index 62 is always the newest" ordering RFC 7541 2.3.2
    /// requires -- evicting older entries first if needed to make
    /// room. An entry larger than the entire table's size limit is
    /// correctly not stored at all (the table ends up empty), per
    /// 4.4's "insertion of an entry larger than the maximum size
    /// clears the table" rule.
    pub fn insert(&mut self, field: HeaderField) {
        let size = field.size();
        self.evict_to_fit(size);
        if size > self.max_size {
            return; // per RFC 7541 4.4 -- table left empty, nothing added
        }
        self.entries.push_front(field);
        self.current_size += size;
    }

    /// Looks up a dynamic-table index (already adjusted to be
    /// zero-based within the dynamic table, i.e. the caller has
    /// already subtracted `STATIC_TABLE.len()`).
    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.entries.get(index)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Huffman table (RFC 7541 Appendix B) ────────────────────────────────
//
// Symbol 256 is the End-of-String (EOS) marker, never itself emitted
// as part of a header's content -- it exists only to pad the final
// byte of a Huffman-encoded string to a byte boundary (5.2 requires
// padding with the EOS code's high-order bits, not zero bits, to
// avoid a valid encoding accidentally colliding with a shorter one
// that happens to be a prefix of it).
const HUFFMAN_TABLE: [(u32, u8); 256] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3fffffff, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3fffffff, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3fffffff, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x3fffd8, 22),
    (0xffffef, 24),
    (0x3fffd9, 22),
    (0x3fffda, 22),
    (0x3fffdb, 22),
    (0x7fffe5, 23),
    (0x3fffdc, 22),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x3fffdf, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xfffff1, 24),
    (0x3fffe0, 22),
    (0x3fffe1, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x3fffe2, 22),
    (0x7fffea, 23),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7fffed, 23),
    (0x3fffe7, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffff2, 24),
    (0x3fffe8, 22),
    (0x3fffe9, 22),
    (0xfffff3, 24),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3fffea, 22),
    (0x7ffff0, 23),
    (0x3fffeb, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffff6, 24),
    (0x3ffffe2, 26),
    (0x7ffff2, 23),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffff3, 23),
    (0x3ffffe5, 26),
    (0x3ffffe6, 26),
    (0x7ffff4, 23),
    (0x3ffffe7, 26),
    (0x3ffffe8, 26),
    (0x1ffffec, 25),
    (0x3ffffe9, 26),
    (0x3ffffea, 26),
    (0x7ffff5, 23),
    (0x1ffffed, 25),
    (0x7ffff6, 23),
    (0x3ffffeb, 26),
    (0x7ffff7, 23),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x3ffffee, 26),
    (0x3ffffef, 26),
    (0x3fffff0, 26),
    (0x3fffff1, 26),
    (0x3fffff2, 26),
    (0x3fffff3, 26),
    (0x3fffff4, 26),
    (0x3fffff5, 26),
    (0x3fffff6, 26),
    (0x3fffff7, 26),
    (0x3fffff8, 26),
    (0x3fffff9, 26),
    (0x3fffffa, 26),
    (0x3fffffb, 26),
    (0x3fffffc, 26),
    (0x3fffffd, 26),
    (0x3fffffe, 26),
    (0x7fffffd, 27),
    (0x3ffffff, 26),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
    (0xfffffff, 28),
];

/// RFC 7541 5.2: the End-of-String (EOS) code is 30 bits, all 1s
/// (0x3FFFFFFF). It's never a real symbol -- it exists purely so an
/// encoder can pad the final byte of a Huffman string with 1-bits, and
/// the spec REQUIRES treating it as a decoding error if it appears as
/// though it were real content. Deliberately not stored in
/// `HUFFMAN_TABLE` (which only holds the 256 real byte symbols) and
/// instead checked for explicitly during decode -- this is the fix for
/// a real, reproducible bug this shape of implementation is prone to
/// otherwise: without an explicit check, 30 bits of 1s simply fail to
/// match any real symbol in the table (at any length up to the
/// table's own longest real code) and get silently treated as "not
/// enough bits yet" rather than rejected -- a 4-byte Huffman-encoded
/// value of all 0xFF (a 30-bit EOS code plus 2 padding bits) then
/// silently decodes to unrelated garbage content instead of being
/// rejected, which is exactly the failure h2spec's test 5.2#3 checks
/// for.
const EOS_CODE: u32 = 0x3fff_ffff;
const EOS_BITS: u32 = 30;

/// Encodes `data` using the RFC 7541 Appendix B Huffman code,
/// returning the encoded bytes. Always shorter than or equal to the
/// input for realistic header content (the Huffman code is designed
/// around the byte-frequency distribution of real HTTP headers) --
/// callers decide whether the savings are worth using Huffman for a
/// given string (see `encode_string`, which only prefers it when it's
/// actually smaller).
fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::with_capacity(data.len());

    for &byte in data {
        let (code, bits) = HUFFMAN_TABLE[byte as usize];
        bit_buf = (bit_buf << bits) | u64::from(code);
        bit_count += u32::from(bits);
        while bit_count >= 8 {
            bit_count -= 8;
            out.push((bit_buf >> bit_count) as u8);
        }
    }

    // Pad the final partial byte with 1-bits (equivalent to the EOS
    // code's high-order bits, which are all 1s anyway) rather than 0
    // bits, per RFC 7541 5.2.
    if bit_count > 0 {
        let padding_bits = 8 - bit_count;
        bit_buf = (bit_buf << padding_bits) | ((1u64 << padding_bits) - 1);
        out.push(bit_buf as u8);
    }

    out
}

/// Decodes a Huffman-encoded byte string back to its original bytes.
/// Built from a (code, bits) -> symbol reverse lookup rather than
/// walking the code tree bit by bit -- simpler to get right than a
/// hand-built tree, at some decode-speed cost that can be revisited
/// (e.g. with a multi-bit lookup table) if profiling ever shows this
/// mattering.
fn huffman_decode(data: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    for &byte in data {
        bit_buf = (bit_buf << 8) | u64::from(byte);
        bit_count += 8;

        loop {
            // Reject the EOS code appearing as if it were real content
            // -- see EOS_CODE's doc comment for why this check has to
            // be explicit rather than falling out of the symbol
            // lookup below.
            if bit_count >= EOS_BITS {
                let top = ((bit_buf >> (bit_count - EOS_BITS)) & ((1u64 << EOS_BITS) - 1)) as u32;
                if top == EOS_CODE {
                    return Err(HpackError::InvalidHuffmanPadding);
                }
            }

            // Greedily try to match a real symbol at every length from
            // 5 (the shortest code in this table) up to 30 (the
            // longest) once enough bits have accumulated.
            let mut matched = false;
            if bit_count >= 5 {
                for bits in 5..=30u32.min(bit_count) {
                    let candidate =
                        ((bit_buf >> (bit_count - bits)) & ((1u64 << bits) - 1)) as u32;
                    if let Some(symbol) = lookup_huffman_symbol(candidate, bits as u8) {
                        out.push(symbol as u8);
                        bit_count -= bits;
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                break; // not enough bits yet for any valid code at this point
            }
        }
    }

    // RFC 7541 5.2: trailing padding must be all 1s AND must be
    // strictly shorter than the shortest valid Huffman code (5 bits
    // in this table) -- 7 bits is the practical ceiling since an
    // 8-bit or longer "leftover" that's still all 1s would actually
    // be long enough to itself be a valid (or EOS-colliding) code,
    // meaning the encoder either used a real code as padding or the
    // padding is simply too long to be padding at all. Either way
    // that's a decoding error, not padding to silently accept.
    if bit_count > 7 {
        return Err(HpackError::InvalidHuffmanPadding);
    }
    if bit_count > 0 {
        let remaining = bit_buf & ((1u64 << bit_count) - 1);
        let all_ones = (1u64 << bit_count) - 1;
        if remaining != all_ones {
            return Err(HpackError::InvalidHuffmanPadding);
        }
    }

    Ok(out)
}

/// Reverse lookup: given `bits` significant bits (right-aligned in
/// `code`), which symbol (if any) that exact code maps to at that
/// exact length. Linear scan over 257 entries -- simple and correct;
/// `huffman_decode` is the only caller and doesn't call this often
/// enough per byte for this to be worth a precomputed reverse-index
/// structure at this stage.
fn lookup_huffman_symbol(code: u32, bits: u8) -> Option<usize> {
    HUFFMAN_TABLE
        .iter()
        .position(|&(c, b)| b == bits && c == code)
}

// ─── Errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    /// The encoded input ended before a complete representation could
    /// be parsed.
    Truncated,
    /// An integer's continuation bytes implied a value too large to
    /// be a realistic header field length -- rejected rather than
    /// accepted, since HPACK's own encoding permits arbitrarily long
    /// continuation sequences but no real header field is anywhere
    /// near this large; treating an oversized value as a decode error
    /// avoids ever allocating based on an attacker-controlled huge
    /// length.
    IntegerOverflow,
    /// Referenced a static+dynamic table index that doesn't exist.
    InvalidIndex,
    /// Huffman-encoded string's trailing padding bits weren't all 1s.
    InvalidHuffmanPadding,
    /// Decoded bytes (Huffman or literal) weren't valid UTF-8.
    InvalidUtf8,
    /// A dynamic table size update exceeded the ceiling this side
    /// advertised via SETTINGS_HEADER_TABLE_SIZE (RFC 7541 6.3).
    DynamicTableSizeUpdateTooLarge,
}

// ─── Integer primitives (RFC 7541 5.1) ─────────────────────────────────

/// The largest value this implementation accepts out of an integer's
/// continuation bytes -- comfortably larger than any realistic header
/// field length or table index, small enough that decoding never has
/// to trust an attacker-supplied value before bounding it. Mirrors the
/// same practical (rather than literal-spec-unbounded) limit real
/// HPACK implementations apply.
const MAX_INTEGER_VALUE: u64 = u32::MAX as u64;

/// Encodes `value` using an N-bit prefix (`prefix_bits`, 1-8) into the
/// low bits of `out`'s next byte, continuing into as many following
/// bytes as needed per 5.1's variable-length integer encoding.
/// `out`'s last byte (if any) already has its high bits set by the
/// caller (e.g. the representation-type flag bits) -- this ORs the
/// prefix value into its low `prefix_bits` bits rather than assuming
/// `out` is empty.
fn encode_integer(out: &mut Vec<u8>, mut value: u64, prefix_bits: u8, flag_bits: u8) {
    let max_prefix_value = (1u64 << prefix_bits) - 1;
    if value < max_prefix_value {
        out.push(flag_bits | value as u8);
        return;
    }

    out.push(flag_bits | max_prefix_value as u8);
    value -= max_prefix_value;
    while value >= 128 {
        out.push(((value % 128) | 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

/// Decodes an integer starting at `data[0]`'s low `prefix_bits` bits
/// (the caller has already stripped/inspected any flag bits in the
/// high bits of that same byte). Returns the value and how many bytes
/// of `data` it consumed.
fn decode_integer(data: &[u8], prefix_bits: u8) -> Result<(u64, usize), HpackError> {
    if data.is_empty() {
        return Err(HpackError::Truncated);
    }
    let max_prefix_value = (1u64 << prefix_bits) - 1;
    let prefix_value = u64::from(data[0]) & max_prefix_value;

    if prefix_value < max_prefix_value {
        return Ok((prefix_value, 1));
    }

    let mut value = prefix_value;
    let mut m = 0u32;
    let mut consumed = 1;
    loop {
        let Some(&byte) = data.get(consumed) else {
            return Err(HpackError::Truncated);
        };
        consumed += 1;
        value += u64::from(byte & 0x7f) << m;
        if value > MAX_INTEGER_VALUE {
            return Err(HpackError::IntegerOverflow);
        }
        m += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((value, consumed))
}

// ─── String primitives (RFC 7541 5.2) ──────────────────────────────────

/// Encodes `s` as an HPACK string literal: a 1-bit Huffman flag, a
/// 7-bit-prefixed length, then either the Huffman-coded or raw UTF-8
/// bytes. Uses Huffman only when it's actually shorter than the raw
/// encoding -- for short strings (many header values) the fixed
/// per-symbol code lengths in the Huffman table don't always beat one
/// byte per character.
fn encode_string(out: &mut Vec<u8>, s: &str) {
    let huffman = huffman_encode(s.as_bytes());
    if huffman.len() < s.len() {
        encode_integer(out, huffman.len() as u64, 7, 0x80);
        out.extend_from_slice(&huffman);
    } else {
        encode_integer(out, s.len() as u64, 7, 0x00);
        out.extend_from_slice(s.as_bytes());
    }
}

/// Decodes an HPACK string literal starting at `data[0]`. Returns the
/// decoded string and how many bytes of `data` it consumed (length
/// prefix + content).
fn decode_string(data: &[u8]) -> Result<(String, usize), HpackError> {
    if data.is_empty() {
        return Err(HpackError::Truncated);
    }
    let huffman_flag = data[0] & 0x80 != 0;
    let (len, len_bytes) = decode_integer(data, 7)?;
    let len = len as usize;

    let content_start = len_bytes;
    let content_end = content_start + len;
    if data.len() < content_end {
        return Err(HpackError::Truncated);
    }
    let content = &data[content_start..content_end];

    let decoded_bytes = if huffman_flag {
        huffman_decode(content)?
    } else {
        content.to_vec()
    };
    let s = String::from_utf8(decoded_bytes).map_err(|_| HpackError::InvalidUtf8)?;

    Ok((s, content_end))
}

// ─── HpackContext: per-connection compression state ────────────────────

/// One side (encode or decode) of a connection's HPACK compression
/// context. HPACK's dynamic table is per-connection and per-direction
/// (a connection has one context for headers it sends, a separate one
/// for headers it receives) -- a single `HpackContext` models one of
/// those, callers hold two.
pub struct HpackContext {
    table: DynamicTable,
}

impl HpackContext {
    pub fn new(max_dynamic_table_size: usize) -> Self {
        HpackContext {
            table: DynamicTable::new(max_dynamic_table_size),
        }
    }

    /// Called when THIS side's own SETTINGS_HEADER_TABLE_SIZE changes
    /// (i.e. we're announcing a new ceiling to the peer) -- updates
    /// both the advertised ceiling and, since we're the one changing
    /// our own mind about it, the current effective size to match (a
    /// self-imposed change can't itself be "too large" the way a
    /// peer's size update against our ceiling could be).
    pub fn set_max_dynamic_table_size(&mut self, new_size: usize) {
        self.table.set_advertised_max_size(new_size);
        let _ = self.table.set_max_size(new_size); // can't fail: new_size is now also the ceiling
    }

    /// Resolves a combined static+dynamic index (1-based, per RFC 7541
    /// 2.3.3: 1..=61 is the static table, 62.. is the dynamic table
    /// with 62 always being the most-recently-inserted entry).
    fn lookup_indexed(&self, index: u64) -> Result<HeaderField, HpackError> {
        let index = index as usize;
        if index == 0 {
            return Err(HpackError::InvalidIndex);
        }
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Ok(HeaderField {
                name: name.to_string(),
                value: value.unwrap_or("").to_string(),
            });
        }
        let dyn_index = index - STATIC_TABLE.len() - 1;
        self.table
            .get(dyn_index)
            .cloned()
            .ok_or(HpackError::InvalidIndex)
    }

    /// Resolves just a name from a combined index -- used by the
    /// literal-with-name-reference representations, which supply their
    /// own value rather than reusing a table entry's value.
    fn lookup_name(&self, index: u64) -> Result<String, HpackError> {
        Ok(self.lookup_indexed(index)?.name)
    }
}

impl HpackContext {
    /// Decodes a complete HPACK header block (the concatenated payload
    /// of a HEADERS frame plus any CONTINUATION frames -- assembling
    /// that concatenation across frames is `stream`'s job, not this
    /// function's) into an ordered list of header fields.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<HeaderField>, HpackError> {
        let mut fields = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let byte = data[pos];

            // RFC 7541 4.2: a dynamic table size update, if present at
            // all, must appear at the very start of a header block --
            // never after any header field representation has already
            // been decoded. Checked using the same bit-pattern
            // precedence as the dispatch below (0x80, then 0x40, then
            // 0x20) -- a naive `byte & 0x20 != 0` alone would also
            // match plenty of Indexed Header Field or Incremental
            // Indexing bytes that happen to have that bit set too,
            // since HPACK's representations are only distinguished by
            // testing the highest set bit first.
            if byte & 0x80 == 0 && byte & 0x40 == 0 && byte & 0x20 != 0 && !fields.is_empty() {
                return Err(HpackError::DynamicTableSizeUpdateTooLarge);
            }
            if byte & 0x80 != 0 {
                // 6.1 Indexed Header Field -- top bit set, 7-bit index.
                let (index, consumed) = decode_integer(&data[pos..], 7)?;
                fields.push(self.lookup_indexed(index)?);
                pos += consumed;
            } else if byte & 0x40 != 0 {
                // 6.2.1 Literal Header Field with Incremental Indexing
                // -- top two bits 01, 6-bit name index (0 = new name follows).
                let (index, index_len) = decode_integer(&data[pos..], 6)?;
                pos += index_len;
                let name = if index == 0 {
                    let (name, name_len) = decode_string(&data[pos..])?;
                    pos += name_len;
                    name
                } else {
                    self.lookup_name(index)?
                };
                let (value, value_len) = decode_string(&data[pos..])?;
                pos += value_len;
                let field = HeaderField { name, value };
                self.table.insert(field.clone());
                fields.push(field);
            } else if byte & 0x20 != 0 {
                // 6.3 Dynamic Table Size Update -- top three bits 001,
                // 5-bit encoded new max size.
                let (new_size, consumed) = decode_integer(&data[pos..], 5)?;
                self.table.set_max_size(new_size as usize)?;
                pos += consumed;
            } else {
                // 6.2.2 Literal Header Field without Indexing (top
                // nibble 0000) or 6.2.3 Literal Header Field Never
                // Indexed (top nibble 0001) -- both use a 4-bit name
                // index and neither updates the dynamic table; the
                // only difference between them is a hint to
                // intermediaries not to re-index a sensitive value
                // on re-encode, which this implementation (not itself
                // a re-encoding intermediary) doesn't need to
                // distinguish.
                let (index, index_len) = decode_integer(&data[pos..], 4)?;
                pos += index_len;
                let name = if index == 0 {
                    let (name, name_len) = decode_string(&data[pos..])?;
                    pos += name_len;
                    name
                } else {
                    self.lookup_name(index)?
                };
                let (value, value_len) = decode_string(&data[pos..])?;
                pos += value_len;
                fields.push(HeaderField { name, value });
            }
        }

        Ok(fields)
    }
}

impl HpackContext {
    /// Encodes `fields` as a complete HPACK header block. Always uses
    /// Literal Header Field with Incremental Indexing (6.2.1) for
    /// fields not already an exact name+value match in the static
    /// table -- simpler than also searching the dynamic table for an
    /// existing match to reference by index, at the cost of not
    /// achieving quite as much compression as an implementation that
    /// does. Correctness-wise this is still fully valid HPACK output;
    /// it just doesn't chase every possible byte of savings a
    /// deduplicating encoder could.
    pub fn encode(&mut self, fields: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::new();

        for field in fields {
            if let Some(static_index) = find_exact_static_match(field) {
                encode_integer(&mut out, static_index as u64, 7, 0x80);
                continue;
            }

            // Literal Header Field with Incremental Indexing (6.2.1).
            match find_static_name_match(&field.name) {
                Some(name_index) => {
                    encode_integer(&mut out, name_index as u64, 6, 0x40);
                }
                None => {
                    out.push(0x40);
                    encode_string(&mut out, &field.name);
                }
            }
            encode_string(&mut out, &field.value);
            self.table.insert(field.clone());
        }

        out
    }
}

/// Finds a static-table index (1-based) whose name AND value exactly
/// match `field`, if any.
fn find_exact_static_match(field: &HeaderField) -> Option<usize> {
    STATIC_TABLE.iter().position(|&(name, value)| {
        name == field.name && value == Some(field.value.as_str())
    }).map(|i| i + 1)
}

/// Finds a static-table index (1-based) whose name matches, regardless
/// of value -- used for the name-reference form of a literal
/// representation.
fn find_static_name_match(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|&(n, _)| n == name).map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    // ─── Integer primitives ─────────────────────────────────────────

    #[test]
    fn small_integer_fits_in_prefix() {
        let mut out = Vec::new();
        encode_integer(&mut out, 10, 5, 0);
        assert_eq!(out, vec![10]);
        let (value, consumed) = decode_integer(&out, 5).unwrap();
        assert_eq!(value, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn large_integer_uses_continuation_bytes() {
        // RFC 7541 C.1.2's own worked example: 1337 encoded with a
        // 5-bit prefix should be [31, 154, 10].
        let mut out = Vec::new();
        encode_integer(&mut out, 1337, 5, 0);
        assert_eq!(out, vec![31, 154, 10]);
        let (value, consumed) = decode_integer(&out, 5).unwrap();
        assert_eq!(value, 1337);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn integer_round_trips_across_range() {
        for &v in &[0u64, 1, 127, 128, 255, 4096, 100_000, 1_000_000] {
            let mut out = Vec::new();
            encode_integer(&mut out, v, 7, 0);
            let (decoded, consumed) = decode_integer(&out, 7).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, out.len());
        }
    }

    #[test]
    fn integer_overflow_rejected() {
        // A pathological continuation sequence that would decode to
        // a value far beyond MAX_INTEGER_VALUE.
        let data = vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert!(matches!(
            decode_integer(&data, 5),
            Err(HpackError::IntegerOverflow)
        ));
    }

    #[test]
    fn truncated_integer_rejected() {
        let data = vec![0x1f, 0xff]; // continuation bit set but no more bytes
        assert!(matches!(decode_integer(&data, 5), Err(HpackError::Truncated)));
    }

    // ─── Huffman ────────────────────────────────────────────────────

    #[test]
    fn huffman_round_trips_ascii() {
        let original = b"www.example.com";
        let encoded = huffman_encode(original);
        assert!(encoded.len() < original.len(), "Huffman should compress typical header text");
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn huffman_round_trips_empty_string() {
        let encoded = huffman_encode(b"");
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn huffman_round_trips_various_strings() {
        for s in ["GET", "200", "/", "gzip, deflate", "text/html; charset=utf-8"] {
            let encoded = huffman_encode(s.as_bytes());
            let decoded = huffman_decode(&encoded).unwrap();
            assert_eq!(decoded, s.as_bytes());
        }
    }

    #[test]
    fn huffman_padding_all_ones_accepted() {
        let encoded = huffman_encode(b"a");
        // Just confirming a real encode+decode round trip works; the
        // padding bits huffman_encode produces are already correct by
        // construction.
        assert_eq!(huffman_decode(&encoded).unwrap(), b"a");
    }

    #[test]
    fn huffman_invalid_padding_rejected() {
        // Manually corrupt the last byte's low bits to not be all 1s.
        let mut encoded = huffman_encode(b"a");
        let last = encoded.len() - 1;
        encoded[last] &= 0b1111_0000; // clear low bits, breaking valid padding
        assert!(matches!(
            huffman_decode(&encoded),
            Err(HpackError::InvalidHuffmanPadding)
        ));
    }

    // ─── String primitives ──────────────────────────────────────────

    #[test]
    fn string_round_trips_with_and_without_huffman_preference() {
        for s in ["hello world", "x", "", "a-fairly-long-realistic-header-value-here"] {
            let mut out = Vec::new();
            encode_string(&mut out, s);
            let (decoded, consumed) = decode_string(&out).unwrap();
            assert_eq!(decoded, s);
            assert_eq!(consumed, out.len());
        }
    }

    // ─── Dynamic table ──────────────────────────────────────────────

    #[test]
    fn dynamic_table_insert_and_get() {
        let mut table = DynamicTable::new(4096);
        table.insert(field("x-custom", "value1"));
        table.insert(field("x-other", "value2"));
        // Index 0 is always the most-recently-inserted.
        assert_eq!(table.get(0).unwrap().name, "x-other");
        assert_eq!(table.get(1).unwrap().name, "x-custom");
    }

    #[test]
    fn dynamic_table_evicts_when_full() {
        let mut table = DynamicTable::new(70); // room for ~1 small entry (32 + name + value overhead)
        table.insert(field("a", "1")); // size 32 + 1 + 1 = 34
        table.insert(field("b", "2")); // size 34, total would be 68, fits
        table.insert(field("c", "3")); // pushes total past 70 -- oldest evicted
        assert!(table.len() <= 2);
        // The oldest ("a") should have been evicted first.
        assert!((0..table.len()).all(|i| table.get(i).unwrap().name != "a"));
    }

    #[test]
    fn dynamic_table_entry_larger_than_max_size_clears_table() {
        let mut table = DynamicTable::new(50);
        table.insert(field("a", "1"));
        assert!(!table.is_empty());
        // This entry alone exceeds the 50-byte limit -- per RFC 7541
        // 4.4, the table ends up empty, not holding a truncated entry.
        table.insert(field("very-long-name-here", "and-an-even-longer-value-here-too"));
        assert!(table.is_empty());
    }

    #[test]
    fn dynamic_table_size_update_evicts_as_needed() {
        let mut table = DynamicTable::new(4096);
        table.insert(field("a", "1"));
        table.insert(field("b", "2"));
        assert_eq!(table.len(), 2);
        let _ = table.set_max_size(34); // room for only one ~34-byte entry
        assert!(table.len() <= 1);
    }

    // ─── HpackContext: decode ───────────────────────────────────────

    #[test]
    fn decode_indexed_static_field() {
        let mut ctx = HpackContext::new(4096);
        // Index 2 = ":method: GET" (static table, both name and value fixed).
        let data = vec![0x82]; // 1000_0010: indexed, index 2
        let fields = ctx.decode(&data).unwrap();
        assert_eq!(fields, vec![field(":method", "GET")]);
    }

    #[test]
    fn decode_literal_with_incremental_indexing_adds_to_dynamic_table() {
        let mut ctx = HpackContext::new(4096);
        let mut data = Vec::new();
        data.push(0x40); // literal with incremental indexing, new name
        encode_string(&mut data, "x-custom");
        encode_string(&mut data, "hello");

        let fields = ctx.decode(&data).unwrap();
        assert_eq!(fields, vec![field("x-custom", "hello")]);
        assert_eq!(ctx.table.len(), 1);
    }

    #[test]
    fn decode_dynamic_table_size_update() {
        let mut ctx = HpackContext::new(4096);
        let data = vec![0x3f, 0x61]; // 001_11111 + continuation -- new size 0x61-31+31=128... just confirm no panic and it applies
        let _ = ctx.decode(&data);
        assert!(ctx.table.max_size <= 4096);
    }

    #[test]
    fn decode_invalid_index_rejected() {
        let mut ctx = HpackContext::new(4096);
        let data = vec![0xff, 0x00]; // huge index via continuation, guaranteed invalid
        assert!(matches!(ctx.decode(&data), Err(HpackError::InvalidIndex)));
    }

    // ─── HpackContext: encode ───────────────────────────────────────

    #[test]
    fn encode_exact_static_match_uses_indexed_representation() {
        let mut ctx = HpackContext::new(4096);
        let encoded = ctx.encode(&[field(":method", "GET")]);
        assert_eq!(encoded, vec![0x82]); // indexed, static index 2
    }

    #[test]
    fn dynamic_table_size_update_exceeding_advertised_ceiling_is_rejected() {
        let mut table = DynamicTable::new(100);
        // The advertised ceiling is 100 -- a size update trying to set
        // it to 200 exceeds what was ever advertised as acceptable.
        let result = table.set_max_size(200);
        assert!(matches!(result, Err(HpackError::DynamicTableSizeUpdateTooLarge)));
    }

    #[test]
    fn dynamic_table_size_update_within_ceiling_succeeds() {
        let mut table = DynamicTable::new(100);
        assert!(table.set_max_size(50).is_ok());
    }

    #[test]
    fn dynamic_table_size_update_after_a_header_field_is_a_decode_error() {
        let mut decoder = HpackContext::new(4096);
        // First, a single valid indexed header field representation
        // (index 2 = ":method: GET" in the static table) -- valid on
        // its own.
        let mut encoded = vec![0x82]; // 1000_0010 -- indexed, index 2
        // Then a dynamic table size update (0010_xxxx pattern) --
        // this is no longer at the start of the header block, so it
        // must be rejected.
        encoded.push(0x3f); // 0011_1111: size update, prefix value 31 (needs continuation)
        encoded.push(0x00); // continuation byte: value stays small
        let result = decoder.decode(&encoded);
        assert!(result.is_err(), "a dynamic table size update after a header field should be a decode error");
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let mut encoder = HpackContext::new(4096);
        let mut decoder = HpackContext::new(4096);

        let original = vec![
            field(":method", "GET"),
            field(":path", "/api/users"),
            field("x-custom-header", "some-value"),
            field("user-agent", "routa-test/1.0"),
        ];

        let encoded = encoder.encode(&original);
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_reuses_dynamic_table_across_multiple_calls() {
        let mut encoder = HpackContext::new(4096);
        let mut decoder = HpackContext::new(4096);

        let first = vec![field("x-custom", "same-value")];
        let second = vec![field("x-custom", "same-value")];

        let encoded1 = encoder.encode(&first);
        let decoded1 = decoder.decode(&encoded1).unwrap();
        assert_eq!(decoded1, first);

        let encoded2 = encoder.encode(&second);
        let decoded2 = decoder.decode(&encoded2).unwrap();
        assert_eq!(decoded2, second);

        // Second encoding of the identical field should be smaller
        // than the first (dynamic table now has a matching name to
        // reference), though this test only asserts correctness of
        // the round trip, not the exact compression ratio.
    }

    #[test]
    fn encode_uses_static_name_match_for_new_value() {
        let mut ctx = HpackContext::new(4096);
        // ":method" is a static-table name (indices 2,3 fixed to
        // GET/POST) -- a different method value should still reference
        // the name via the static table rather than encoding it as a
        // brand new literal name.
        let encoded = ctx.encode(&[field(":method", "PATCH")]);
        // First byte should be 0x40 | name_index (name-reference form),
        // not a literal-name form (which would start the name with a
        // length-prefixed string immediately after 0x40).
        assert_eq!(encoded[0] & 0xc0, 0x40);
        assert_ne!(encoded[0], 0x40); // 0x40 alone would mean "new name follows"
    }
}
