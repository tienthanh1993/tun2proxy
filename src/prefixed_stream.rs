use std::{
    io::{self, Cursor},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that reads from a prefix buffer first, then the inner stream.
pub struct PrefixedTcpStream<S> {
    stream: S,
    prefix: Cursor<Vec<u8>>,
}

impl<S> PrefixedTcpStream<S> {
    pub fn new(stream: S, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix: Cursor::new(prefix),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let prefix = &mut this.prefix;
        let prefix_rem = prefix.get_ref().len() as u64 - prefix.position();
        if prefix_rem > 0 {
            let n = std::cmp::min(prefix_rem as usize, buf.remaining());
            let pos = prefix.position() as usize;
            buf.put_slice(&prefix.get_ref()[pos..pos + n]);
            prefix.set_position(prefix.position() + n as u64);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
