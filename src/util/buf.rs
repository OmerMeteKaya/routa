//! A growable byte buffer with a read offset, tuned for the
//! append-then-consume-from-the-front pattern connection I/O needs:
//! bytes accumulate at the back (as more data arrives, or more response
//! body is produced) and get consumed from the front (as they're
//! parsed, or written out to the socket) at a different rate. `Buf`
//! tracks how much of its front has already been consumed via `off`
//! rather than shifting the remaining bytes down on every consume --
//! see `push`'s doc comment for why that distinction matters under a
//! slow-drain pattern (many small appends against a large,
//! slowly-draining body).

const INITIAL_CAP: usize = 4096;

#[derive(Debug)]
pub struct Buf {
    data: Vec<u8>,
    /// How many bytes at the front of `data` have already been
    /// consumed and should be treated as logically absent. Only
    /// reclaimed (via a compaction memmove) when appending would
    /// otherwise require growing the allocation -- see `push`.
    off: usize,
}

impl Buf {
    pub fn new() -> Self {
        Buf {
            data: Vec::new(),
            off: 0,
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Buf {
            data: Vec::with_capacity(cap),
            off: 0,
        }
    }

    /// The unconsumed bytes currently held.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.off..]
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.off
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends `src` to the end of the unconsumed data. Only compacts
    /// (reclaiming the already-consumed prefix via a shift) or grows
    /// the underlying allocation when the append would not otherwise
    /// fit -- compacting on some fixed schedule instead (e.g. whenever
    /// the consumed prefix crosses half of capacity, regardless of
    /// whether an append actually needs the space) turns into
    /// repeated, unnecessary large copies under a slow-drain pattern:
    /// many small appends against a body that's draining out slower
    /// than it's filling, where the consumed prefix creeps up while
    /// the unconsumed tail stays large. Compacting only when it
    /// actually avoids a strictly more expensive reallocation keeps
    /// the amortized cost per append proportional to what was
    /// appended, not to how much unconsumed data happens to be sitting
    /// in the buffer.
    pub fn push(&mut self, src: &[u8]) {
        if src.is_empty() {
            return;
        }

        let needed = self.off + self.len() + src.len();
        if needed > self.data.capacity() {
            let unconsumed_len = self.len();
            if self.off > 0 && unconsumed_len + src.len() <= self.data.capacity() {
                // Reclaiming the consumed prefix makes room without
                // growing the allocation at all.
                self.data.copy_within(self.off.., 0);
                self.data.truncate(unconsumed_len);
                self.off = 0;
            } else {
                let mut new_cap = if self.data.capacity() == 0 {
                    INITIAL_CAP
                } else {
                    self.data.capacity() * 2
                };
                while new_cap < self.off + unconsumed_len + src.len() {
                    new_cap *= 2;
                }
                self.data.reserve(new_cap - self.data.capacity());
            }
        }

        self.data.extend_from_slice(src);
    }

    pub fn push_str(&mut self, s: &str) {
        self.push(s.as_bytes());
    }

    /// Marks the first `n` unconsumed bytes as consumed. Cheap (just
    /// advances `off`) -- the underlying storage isn't actually
    /// reclaimed until a future `push` needs the room; see `push`'s
    /// doc comment.
    pub fn consume(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n >= self.len() {
            self.off = 0;
            self.data.clear();
            return;
        }
        self.off += n;
    }

    /// Drops all unconsumed data, keeping the underlying allocation for
    /// reuse.
    pub fn reset(&mut self) {
        self.off = 0;
        self.data.clear();
    }
}

impl Default for Buf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_then_read_roundtrips() {
        let mut buf = Buf::new();
        buf.push(b"hello");
        buf.push(b" world");
        assert_eq!(buf.as_slice(), b"hello world");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn consume_advances_without_shifting_data() {
        let mut buf = Buf::new();
        buf.push(b"abcdef");
        buf.consume(3);
        assert_eq!(buf.as_slice(), b"def");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn consume_more_than_len_clears_everything() {
        let mut buf = Buf::new();
        buf.push(b"abc");
        buf.consume(100);
        assert!(buf.is_empty());
        assert_eq!(buf.as_slice(), b"");
    }

    #[test]
    fn push_after_partial_consume_reclaims_prefix_without_growing() {
        // Fill to exactly capacity, consume some of it, then push
        // something that fits in the reclaimed space -- this should
        // NOT need to grow the underlying allocation.
        let mut buf = Buf::with_capacity(16);
        buf.push(b"0123456789012345"); // exactly 16 bytes, at capacity
        let cap_before = buf.data.capacity();
        buf.consume(10); // "0123456789" consumed, "012345" (6 bytes) remain
        buf.push(b"abcd"); // 6 + 4 = 10 bytes, comfortably fits in 16
        assert_eq!(buf.as_slice(), b"012345abcd");
        assert_eq!(
            buf.data.capacity(),
            cap_before,
            "reclaiming the consumed prefix should avoid growing capacity"
        );
    }

    #[test]
    fn push_grows_when_reclaiming_prefix_is_not_enough() {
        let mut buf = Buf::with_capacity(8);
        buf.push(b"12345678"); // fills capacity exactly
        buf.consume(2); // "345678" remain: 6 bytes, not enough headroom for a big push
        buf.push(b"0123456789"); // needs more room than reclaiming 2 bytes gives

        let mut expected = Buf::new();
        expected.push(b"345678"); // what remained after consuming 2 of "12345678"
        expected.push(b"0123456789");
        assert_eq!(buf.as_slice(), expected.as_slice());
    }

    #[test]
    fn reset_clears_data_and_offset() {
        let mut buf = Buf::new();
        buf.push(b"abcdef");
        buf.consume(3);
        buf.reset();
        assert!(buf.is_empty());
        buf.push(b"xyz");
        assert_eq!(buf.as_slice(), b"xyz");
    }

    #[test]
    fn push_str_appends_utf8_bytes() {
        let mut buf = Buf::new();
        buf.push_str("hello");
        buf.push_str(" world");
        assert_eq!(buf.as_slice(), b"hello world");
    }

    #[test]
    fn empty_push_is_a_no_op() {
        let mut buf = Buf::new();
        buf.push(b"abc");
        buf.push(b"");
        assert_eq!(buf.as_slice(), b"abc");
    }
}
