//! Frames on the pipes: a 4-byte little-endian length, then that many bytes of one JSON object.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// The largest frame in either direction. A larger length ends the connection: the peer is broken or hostile.
pub const MAX_FRAME: usize = 1 << 20;

/// Why a frame could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The peer closed the pipe between two frames.
    Closed,
    /// The peer closed the pipe inside a frame.
    Truncated,
    /// The length is 0 or above `MAX_FRAME`.
    BadLength(usize),
    /// The pipe failed.
    Io(std::io::ErrorKind),
}

/// Reads one frame. The buffer is zeroed when it is dropped: a frame can hold a password.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        match r.read(&mut head[got..]).await {
            Ok(0) => {
                return Err(if got == 0 {
                    FrameError::Closed
                } else {
                    FrameError::Truncated
                });
            }
            Ok(n) => got += n,
            Err(e) => return Err(FrameError::Io(e.kind())),
        }
    }
    let len = u32::from_le_bytes(head) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(FrameError::BadLength(len));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    match r.read_exact(&mut body[..]).await {
        Ok(_) => Ok(body),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(e) => Err(FrameError::Io(e.kind())),
    }
}

/// Writes one frame and flushes it.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame size"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    w.write_all(&out).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_frame_round_trips() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, br#"{"id":1}"#).await.unwrap();
        assert_eq!(&buf[..4], &8u32.to_le_bytes());
        let mut r = &buf[..];
        let f = read_frame(&mut r).await.unwrap();
        assert_eq!(&f[..], br#"{"id":1}"#);
        assert_eq!(read_frame(&mut r).await, Err(FrameError::Closed));
    }

    #[tokio::test]
    async fn a_length_above_the_bound_is_refused() {
        let head = ((MAX_FRAME + 1) as u32).to_le_bytes();
        let mut r = &head[..];
        assert_eq!(read_frame(&mut r).await, Err(FrameError::BadLength(MAX_FRAME + 1)));
        let zero = 0u32.to_le_bytes();
        let mut r = &zero[..];
        assert_eq!(read_frame(&mut r).await, Err(FrameError::BadLength(0)));
    }

    #[tokio::test]
    async fn a_cut_frame_is_truncated() {
        let mut buf = 10u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"abc");
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).await, Err(FrameError::Truncated));
        let half = [1u8, 0];
        let mut r = &half[..];
        assert_eq!(read_frame(&mut r).await, Err(FrameError::Truncated));
    }
}
