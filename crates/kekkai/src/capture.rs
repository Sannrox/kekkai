//! Bounded stdout/stderr capture. Dropped bytes are drained so the child
//! cannot fill the pipe.

use std::io::{self, Read};
use std::thread;

use crate::CaptureKeep;

/// Bytes kept from one captured stream, plus truncation metadata.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamCapture {
    /// Kept bytes. Length is at most the configured cap.
    pub bytes: Vec<u8>,
    /// True when any byte was dropped.
    pub truncated: bool,
    /// Number of bytes read and discarded.
    pub dropped: u64,
}

fn drain(mut reader: impl Read, max: usize, keep: CaptureKeep) -> StreamCapture {
    match keep {
        CaptureKeep::Head => drain_head(&mut reader, max),
        CaptureKeep::Tail => drain_tail(&mut reader, max),
        CaptureKeep::HeadAndTail => drain_head_and_tail_one_pass(&mut reader, max),
    }
}

fn drain_head(reader: &mut impl Read, max: usize) -> StreamCapture {
    let mut kept = Vec::new();
    let mut dropped = 0_u64;
    let mut buf = [0_u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if kept.len() < max {
            let take = (max - kept.len()).min(n);
            kept.extend_from_slice(&buf[..take]);
            dropped += (n - take) as u64;
        } else {
            dropped += n as u64;
        }
    }
    StreamCapture {
        truncated: dropped > 0,
        dropped,
        bytes: kept,
    }
}

fn drain_tail(reader: &mut impl Read, max: usize) -> StreamCapture {
    if max == 0 {
        return drain_head(reader, 0);
    }
    let mut ring = vec![0_u8; max];
    let mut len = 0_usize;
    let mut pos = 0_usize;
    let mut dropped = 0_u64;
    let mut buf = [0_u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            if len == max {
                dropped += 1;
            } else {
                len += 1;
            }
            ring[pos] = b;
            pos = (pos + 1) % max;
        }
    }
    let bytes = if len < max {
        ring[..len].to_vec()
    } else {
        let mut out = Vec::with_capacity(max);
        out.extend_from_slice(&ring[pos..]);
        out.extend_from_slice(&ring[..pos]);
        out
    };
    StreamCapture {
        truncated: dropped > 0,
        dropped,
        bytes,
    }
}

fn drain_head_and_tail_one_pass(reader: &mut impl Read, max: usize) -> StreamCapture {
    if max == 0 {
        return drain_head(reader, 0);
    }
    let head_max = max / 2;
    let tail_max = max - head_max;
    let mut head = Vec::new();
    let mut ring = vec![0_u8; tail_max];
    let mut ring_len = 0_usize;
    let mut ring_pos = 0_usize;
    let mut dropped = 0_u64;
    let mut buf = [0_u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            if head.len() < head_max {
                head.push(b);
            } else {
                if ring_len == tail_max {
                    dropped += 1;
                } else {
                    ring_len += 1;
                }
                ring[ring_pos] = b;
                ring_pos = (ring_pos + 1) % tail_max;
            }
        }
    }
    let mut bytes = head;
    if ring_len < tail_max {
        bytes.extend_from_slice(&ring[..ring_len]);
    } else {
        bytes.extend_from_slice(&ring[ring_pos..]);
        bytes.extend_from_slice(&ring[..ring_pos]);
    }
    StreamCapture {
        truncated: dropped > 0,
        dropped,
        bytes,
    }
}

pub(crate) fn spawn_drain<R: Read + Send + 'static>(
    reader: Option<R>,
    max: Option<usize>,
    keep: CaptureKeep,
) -> Option<thread::JoinHandle<StreamCapture>> {
    let (reader, max) = match (reader, max) {
        (Some(reader), Some(max)) => (reader, max),
        _ => return None,
    };
    Some(thread::spawn(move || drain(reader, max, keep)))
}

pub(crate) fn join_drain(handle: Option<thread::JoinHandle<StreamCapture>>) -> StreamCapture {
    match handle {
        Some(handle) => handle.join().unwrap_or_default(),
        None => StreamCapture::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn seq(n: u8) -> Vec<u8> {
        (0..n).collect()
    }

    #[test]
    fn head_keeps_prefix_and_counts_dropped() {
        let cap = drain(Cursor::new(seq(100)), 10, CaptureKeep::Head);
        assert_eq!(cap.bytes, seq(10));
        assert!(cap.truncated);
        assert_eq!(cap.dropped, 90);
    }

    #[test]
    fn tail_keeps_suffix_and_counts_dropped() {
        let cap = drain(Cursor::new(seq(100)), 10, CaptureKeep::Tail);
        assert_eq!(cap.bytes, (90..100).collect::<Vec<_>>());
        assert!(cap.truncated);
        assert_eq!(cap.dropped, 90);
    }

    #[test]
    fn head_and_tail_keeps_both_ends() {
        let cap = drain(Cursor::new(seq(100)), 20, CaptureKeep::HeadAndTail);
        let mut want = seq(10);
        want.extend(90..100);
        assert_eq!(cap.bytes, want);
        assert!(cap.truncated);
        assert_eq!(cap.dropped, 80);
    }

    #[test]
    fn under_cap_is_not_truncated() {
        let cap = drain(Cursor::new(seq(8)), 20, CaptureKeep::HeadAndTail);
        assert_eq!(cap.bytes, seq(8));
        assert!(!cap.truncated);
        assert_eq!(cap.dropped, 0);
    }

    #[test]
    fn zero_cap_drops_everything() {
        for keep in [
            CaptureKeep::Head,
            CaptureKeep::Tail,
            CaptureKeep::HeadAndTail,
        ] {
            let cap = drain(Cursor::new(seq(16)), 0, keep);
            assert!(cap.bytes.is_empty(), "{keep:?}");
            assert!(cap.truncated, "{keep:?}");
            assert_eq!(cap.dropped, 16, "{keep:?}");
        }
    }
}
