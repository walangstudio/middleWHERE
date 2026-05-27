//! MySQL packet framing.
//!
//! Each packet is `[len_lo, len_mid, len_hi, seq][payload..]` where the length
//! is the payload length only. Sequence numbers wrap modulo 256 and reset on
//! every new command phase, but during handshake the server and client share
//! one increasing counter.
//!
//! This module deliberately does NOT support packets >= 2^24 - 1 (the
//! continuation/split case). We only handle one-packet payloads here; the
//! handshake never exceeds 1 KB and command packets we generate stay under
//! 16 MB. If we ever need larger, callers must split.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_PAYLOAD: usize = (1 << 24) - 1;

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("payload too large: {0}")]
    PayloadTooLarge(usize),
    #[error("unexpected EOF reading {what}")]
    UnexpectedEof { what: &'static str },
    #[error("multi-packet payloads not supported")]
    MultiPacket,
}

#[derive(Debug, Default)]
pub struct SequenceCounter(pub u8);

impl SequenceCounter {
    pub fn reset(&mut self) {
        self.0 = 0;
    }
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u8 {
        let v = self.0;
        self.0 = self.0.wrapping_add(1);
        v
    }
    pub fn expect(&mut self, got: u8) -> Result<(), FramingError> {
        if got != self.0 {
            return Err(FramingError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("out-of-order packet: got seq {}, want {}", got, self.0),
            )));
        }
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    r: &mut R,
    seq: &mut SequenceCounter,
) -> Result<Vec<u8>, FramingError> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(FramingError::UnexpectedEof {
                what: "packet header",
            });
        }
        Err(e) => return Err(e.into()),
    }
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    seq.expect(hdr[3])?;
    if len == MAX_PAYLOAD {
        return Err(FramingError::MultiPacket);
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FramingError::UnexpectedEof {
                what: "packet payload",
            }
        } else {
            FramingError::Io(e)
        }
    })?;
    Ok(payload)
}

pub async fn write_packet<W: AsyncWrite + Unpin>(
    w: &mut W,
    seq: &mut SequenceCounter,
    payload: &[u8],
) -> Result<(), FramingError> {
    if payload.len() >= MAX_PAYLOAD {
        return Err(FramingError::PayloadTooLarge(payload.len()));
    }
    let len = payload.len();
    let hdr = [
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq.next(),
    ];
    w.write_all(&hdr).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-encoded integer (lenenc-int) from the front of `buf`.
/// Returns (value, bytes_consumed).
pub fn read_lenenc_int(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first {
        0x00..=0xFA => Some((first as u64, 1)),
        0xFB => None, // NULL — caller decides what to do
        0xFC => {
            let b = buf.get(1..3)?;
            Some((u16::from_le_bytes([b[0], b[1]]) as u64, 3))
        }
        0xFD => {
            let b = buf.get(1..4)?;
            Some((
                (b[0] as u64) | ((b[1] as u64) << 8) | ((b[2] as u64) << 16),
                4,
            ))
        }
        0xFE => {
            let b = buf.get(1..9)?;
            let mut v = 0u64;
            for (i, byte) in b.iter().enumerate() {
                v |= (*byte as u64) << (i * 8);
            }
            Some((v, 9))
        }
        0xFF => None,
    }
}

pub fn write_lenenc_int(out: &mut Vec<u8>, v: u64) {
    if v < 0xFB {
        out.push(v as u8);
    } else if v <= u16::MAX as u64 {
        out.push(0xFC);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v < (1 << 24) {
        out.push(0xFD);
        out.push((v & 0xFF) as u8);
        out.push(((v >> 8) & 0xFF) as u8);
        out.push(((v >> 16) & 0xFF) as u8);
    } else {
        out.push(0xFE);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Read a NUL-terminated string. Returns (bytes, consumed_including_nul).
pub fn read_nul_string(buf: &[u8]) -> Option<(&[u8], usize)> {
    let pos = buf.iter().position(|&b| b == 0)?;
    Some((&buf[..pos], pos + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_then_read_packet() {
        let (a, b) = tokio::io::duplex(64);
        let (mut ar, _aw) = tokio::io::split(a);
        let (_br, mut bw) = tokio::io::split(b);

        let mut w_seq = SequenceCounter::default();
        let mut r_seq = SequenceCounter::default();

        let payload = b"hello, mysql";
        write_packet(&mut bw, &mut w_seq, payload).await.unwrap();
        let got = read_packet(&mut ar, &mut r_seq).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn out_of_order_seq_rejected() {
        let (a, b) = tokio::io::duplex(64);
        let (mut ar, _aw) = tokio::io::split(a);
        let (_br, mut bw) = tokio::io::split(b);

        let mut w_seq = SequenceCounter::default();
        write_packet(&mut bw, &mut w_seq, b"x").await.unwrap();
        write_packet(&mut bw, &mut w_seq, b"y").await.unwrap();

        let mut r_seq = SequenceCounter(5);
        assert!(read_packet(&mut ar, &mut r_seq).await.is_err());
    }

    #[test]
    fn lenenc_roundtrip() {
        for v in [
            0u64,
            1,
            250,
            251,
            0xFA,
            0xFB,
            0xFFFF,
            0x10000,
            (1u64 << 24) - 1,
            1u64 << 24,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_lenenc_int(&mut out, v);
            let (back, n) = read_lenenc_int(&out).unwrap();
            assert_eq!(back, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn nul_string() {
        let (s, n) = read_nul_string(b"hello\0world").unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(n, 6);
        assert!(read_nul_string(b"no terminator").is_none());
    }
}
