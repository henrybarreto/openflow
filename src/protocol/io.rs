//! Length-driven frame reading and writing over any async stream.
//!
//! An `OpenFlow` message carries its own total length in the header, so
//! framing is just "read 8 bytes, read `length - 8` more". The stateful
//! [`FrameReader`] additionally keeps partial input between calls, which makes
//! its deadline and cancellation-aware methods safe to resume.

use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::protocol::constants::OFP_HEADER_LEN;
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;

/// The default maximum total size of one `OpenFlow` frame.
///
/// `OpenFlow`'s two-byte length field makes this the largest representable
/// frame (`65_535` bytes). Callers that need a tighter application policy can
/// use [`read_frame_with_limit`] or [`FrameReader::with_max_frame_size`].
pub const DEFAULT_MAX_FRAME_SIZE: usize = u16::MAX as usize;

fn unexpected_eof() -> OfError {
    OfError::Io(IoError::new(
        ErrorKind::UnexpectedEof,
        "unexpected end of OpenFlow frame",
    ))
}

/// A resumable, bounded `OpenFlow` frame reader.
///
/// Unlike a one-shot `read_exact` sequence, this reader records how much of
/// the current header/body has arrived. Dropping or timing out a
/// [`FrameReader::read_frame`] future therefore does not lose framing state;
/// the next call resumes at the same byte boundary.
#[derive(Debug)]
pub struct FrameReader<S> {
    stream: S,
    max_frame_size: usize,
    header: [u8; OFP_HEADER_LEN],
    header_read: usize,
    frame: Option<Vec<u8>>,
    body_read: usize,
}

impl<S> FrameReader<S> {
    /// Wrap a stream using [`DEFAULT_MAX_FRAME_SIZE`].
    #[must_use]
    pub const fn new(stream: S) -> Self {
        Self::with_max_frame_size(stream, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Wrap a stream with an explicit maximum total frame size.
    ///
    /// A limit smaller than the `OpenFlow` header is allowed and simply rejects
    /// every frame with [`OfError::FrameTooLarge`]. This makes the limit easy
    /// to use when it comes from configuration without a separate validation
    /// branch.
    #[must_use]
    pub const fn with_max_frame_size(stream: S, max_frame_size: usize) -> Self {
        Self {
            stream,
            max_frame_size,
            header: [0; OFP_HEADER_LEN],
            header_read: 0,
            frame: None,
            body_read: 0,
        }
    }

    /// Return the configured maximum total frame size.
    #[must_use]
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Return a shared reference to the underlying stream.
    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Return a mutable reference to the underlying stream.
    #[must_use]
    pub const fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Take the underlying stream back.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> FrameReader<S>
where
    S: AsyncRead + Unpin,
{
    /// Read the next frame, returning `None` when EOF occurs between frames.
    ///
    /// EOF after any header/body bytes have been consumed is an error because
    /// it leaves a truncated `OpenFlow` frame. The reader retains partial state
    /// if this future is cancelled, so a later call can safely continue.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated frame, malformed length, an oversized
    /// frame, or an underlying stream failure.
    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>> {
        while self.header_read < OFP_HEADER_LEN {
            let header = self
                .header
                .get_mut(self.header_read..)
                .ok_or(OfError::ShortBuffer)?;
            let bytes_read = self.stream.read(header).await?;
            if bytes_read == 0 {
                if self.header_read == 0 {
                    return Ok(None);
                }
                self.reset();
                return Err(unexpected_eof());
            }
            self.header_read += bytes_read;
        }

        if self.frame.is_none() {
            let header = match Header::parse(&self.header) {
                Ok(header) => header,
                Err(error) => {
                    self.reset();
                    return Err(error);
                }
            };
            let total_len = usize::from(header.length);
            if total_len > self.max_frame_size {
                self.reset();
                return Err(OfError::FrameTooLarge {
                    length: header.length,
                    max: self.max_frame_size,
                });
            }

            let mut frame = vec![0u8; total_len];
            frame
                .get_mut(..OFP_HEADER_LEN)
                .ok_or(OfError::ShortBuffer)?
                .copy_from_slice(&self.header);
            self.frame = Some(frame);
        }

        let total_len = self
            .frame
            .as_ref()
            .map(Vec::len)
            .ok_or(OfError::ShortBuffer)?;
        while self.body_read < total_len - OFP_HEADER_LEN {
            let body_offset = OFP_HEADER_LEN + self.body_read;
            let (stream, frame) = (&mut self.stream, &mut self.frame);
            let frame = frame.as_mut().ok_or(OfError::ShortBuffer)?;
            let body = frame.get_mut(body_offset..).ok_or(OfError::ShortBuffer)?;
            let bytes_read = stream.read(body).await?;
            if bytes_read == 0 {
                self.reset();
                return Err(unexpected_eof());
            }
            self.body_read += bytes_read;
        }

        let frame = self.frame.take().ok_or(OfError::ShortBuffer)?;
        self.header_read = 0;
        self.body_read = 0;
        Ok(Some(frame))
    }

    /// Read the next frame with a relative timeout.
    ///
    /// The reader's partial state is retained when the timeout expires, so a
    /// subsequent call can resume safely. `None` still means clean EOF.
    ///
    /// # Errors
    ///
    /// Returns [`OfError::Timeout`] when the timeout expires, or the same
    /// errors as [`Self::read_frame`].
    pub async fn read_frame_with_timeout(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        tokio::time::timeout(timeout, self.read_frame())
            .await
            .map_err(|_| OfError::Timeout)?
    }

    /// Read the next frame until an absolute Tokio deadline.
    ///
    /// This is cancellation-safe in the same way as
    /// [`Self::read_frame_with_timeout`].
    ///
    /// # Errors
    ///
    /// Returns [`OfError::Timeout`] when the deadline expires, or the same
    /// errors as [`Self::read_frame`].
    pub async fn read_frame_until(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        tokio::time::timeout_at(deadline, self.read_frame())
            .await
            .map_err(|_| OfError::Timeout)?
    }

    fn reset(&mut self) {
        self.header_read = 0;
        self.frame = None;
        self.body_read = 0;
    }
}

/// Read a full `OpenFlow` frame from the stream.
///
/// This compatibility helper keeps the original `Result<Vec<u8>>` API. Use
/// [`read_frame_or_eof`] when clean EOF should be distinguished from a
/// truncated frame, or [`FrameReader`] when a read may be cancelled and later
/// resumed.
///
/// # Errors
///
/// Returns an error if the stream closes early or the frame header/body is
/// malformed or exceeds [`DEFAULT_MAX_FRAME_SIZE`].
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    read_frame_with_limit(stream, DEFAULT_MAX_FRAME_SIZE).await
}

/// Read a full frame, distinguishing clean EOF from a truncated frame.
///
/// `Ok(None)` is returned only when EOF is observed before the next frame's
/// first byte. EOF after a partial header or body remains an
/// `UnexpectedEof` I/O error.
///
/// # Errors
///
/// Returns an error if a partial frame is truncated, malformed, or exceeds
/// [`DEFAULT_MAX_FRAME_SIZE`].
pub async fn read_frame_or_eof<S>(stream: &mut S) -> Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    read_frame_or_eof_with_limit(stream, DEFAULT_MAX_FRAME_SIZE).await
}

/// Read a full frame with an explicit maximum total size.
///
/// The frame body is not allocated until the header has been validated and
/// the advertised length has passed `max_frame_size`.
///
/// # Errors
///
/// Returns [`OfError::FrameTooLarge`] when the advertised frame exceeds the
/// limit, or the same errors as [`read_frame`].
pub async fn read_frame_with_limit<S>(stream: &mut S, max_frame_size: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    read_frame_or_eof_with_limit(stream, max_frame_size)
        .await?
        .ok_or_else(unexpected_eof)
}

/// Read a frame with an explicit limit, returning `None` for clean EOF.
///
/// # Errors
///
/// Returns an error for a truncated frame, malformed length, an oversized
/// frame, or an underlying stream failure.
pub async fn read_frame_or_eof_with_limit<S>(
    stream: &mut S,
    max_frame_size: usize,
) -> Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    FrameReader::with_max_frame_size(stream, max_frame_size)
        .read_frame()
        .await
}

/// Read a full frame with the default limit and a relative timeout.
///
/// This one-shot helper preserves the original borrowed-stream shape, but a
/// timeout after partial input cannot preserve that input for a later call.
/// Use [`FrameReader::read_frame_with_timeout`] when the operation must be
/// resumed after cancellation.
///
/// # Errors
///
/// Returns [`OfError::Timeout`] when the timeout expires, or the same errors
/// as [`read_frame`].
pub async fn read_frame_with_timeout<S>(stream: &mut S, timeout: Duration) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, read_frame(stream))
        .await
        .map_err(|_| OfError::Timeout)?
}

/// Write a full `OpenFlow` frame to the stream.
///
/// # Errors
///
/// Returns an error if the frame is malformed or the stream write fails.
pub(crate) async fn write_frame<S>(stream: &mut S, frame: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if frame.len() < OFP_HEADER_LEN {
        return Err(OfError::ShortBuffer);
    }

    let header = Header::parse(frame.get(..OFP_HEADER_LEN).ok_or(OfError::ShortBuffer)?)?;
    if header.length as usize != frame.len() {
        return Err(OfError::InvalidLength(header.length));
    }

    stream.write_all(frame).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::{
        read_frame, read_frame_or_eof, read_frame_with_limit, write_frame, FrameReader,
        DEFAULT_MAX_FRAME_SIZE,
    };
    use crate::protocol::codec::Encoder;
    use crate::protocol::error::OfError;
    use tokio::io::{AsyncWriteExt, DuplexStream};
    use tokio::time::timeout;

    async fn write_header_and_body(stream: &mut DuplexStream, frame: &[u8]) {
        stream.write_all(frame).await.unwrap();
    }

    #[tokio::test]
    async fn write_frame_rejects_a_buffer_shorter_than_a_header() {
        let (mut a, _b) = tokio::io::duplex(64);
        let err = write_frame(&mut a, &[0u8; 4]).await.unwrap_err();
        assert!(matches!(err, OfError::ShortBuffer));
    }

    #[tokio::test]
    async fn write_frame_rejects_a_header_length_mismatched_with_the_buffer() {
        let (mut a, _b) = tokio::io::duplex(64);
        let mut frame = Encoder::barrier_request(1);
        frame.push(0); // one extra byte the header's length field doesn't account for.
        let err = write_frame(&mut a, &frame).await.unwrap_err();
        assert!(matches!(err, OfError::InvalidLength(_)));
    }

    #[tokio::test]
    async fn write_frame_then_read_frame_round_trips_a_valid_message() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let frame = Encoder::barrier_request(7);
        write_frame(&mut a, &frame).await.unwrap();
        let read_back = read_frame(&mut b).await.unwrap();
        assert_eq!(read_back, frame);
    }

    #[tokio::test]
    async fn default_limit_accepts_the_largest_wire_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(DEFAULT_MAX_FRAME_SIZE + 1);
        let mut frame = vec![0u8; DEFAULT_MAX_FRAME_SIZE];
        frame[0] = 6;
        let frame_len = u16::try_from(frame.len()).unwrap();
        frame[2..4].copy_from_slice(&frame_len.to_be_bytes());
        let writer_task = tokio::spawn(async move {
            write_header_and_body(&mut writer, &frame).await;
            frame
        });
        let received = read_frame(&mut reader).await.unwrap();
        assert_eq!(received.len(), DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(received, writer_task.await.unwrap());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_body_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let mut frame = Encoder::barrier_request(9);
        frame[2..4].copy_from_slice(&16u16.to_be_bytes());
        writer.write_all(&frame[..8]).await.unwrap();

        let err = read_frame_with_limit(&mut reader, 8).await.unwrap_err();
        assert!(matches!(err, OfError::FrameTooLarge { length: 16, max: 8 }));
    }

    #[tokio::test]
    async fn clean_eof_is_distinguished_from_partial_eof() {
        let (reader_io, writer_io) = tokio::io::duplex(64);
        drop(writer_io);
        let mut reader = reader_io;
        assert_eq!(read_frame_or_eof(&mut reader).await.unwrap(), None);

        let (mut writer, reader_io) = tokio::io::duplex(64);
        writer.write_all(&[6, 0, 0, 8]).await.unwrap();
        drop(writer);
        let mut reader = reader_io;
        assert!(matches!(
            read_frame_or_eof(&mut reader).await,
            Err(OfError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));

        let (mut writer, reader_io) = tokio::io::duplex(64);
        let mut frame = Encoder::barrier_request(12);
        frame[2..4].copy_from_slice(&12u16.to_be_bytes());
        frame.resize(12, 0);
        writer.write_all(&frame[..10]).await.unwrap();
        drop(writer);
        let mut reader = reader_io;
        assert!(matches!(
            read_frame_or_eof(&mut reader).await,
            Err(OfError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn stateful_reader_resumes_after_timeout() {
        let (mut writer, reader_io) = tokio::io::duplex(64);
        let frame = Encoder::barrier_request(42);
        writer.write_all(&frame[..4]).await.unwrap();

        let mut reader = FrameReader::new(reader_io);
        assert!(matches!(
            reader
                .read_frame_with_timeout(std::time::Duration::from_millis(1))
                .await,
            Err(OfError::Timeout)
        ));

        writer.write_all(&frame[4..]).await.unwrap();
        assert_eq!(reader.read_frame().await.unwrap(), Some(frame));
        assert!(
            timeout(std::time::Duration::from_millis(1), reader.read_frame())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stateful_reader_resumes_after_an_absolute_deadline() {
        let (mut writer, reader_io) = tokio::io::duplex(64);
        let frame = Encoder::barrier_request(43);
        writer.write_all(&frame[..4]).await.unwrap();

        let mut reader = FrameReader::new(reader_io);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
        assert!(matches!(
            reader.read_frame_until(deadline).await,
            Err(OfError::Timeout)
        ));

        writer.write_all(&frame[4..]).await.unwrap();
        assert_eq!(reader.read_frame().await.unwrap(), Some(frame));
    }
}
