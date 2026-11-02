//! The only POSIX ownership/syscall boundary besides C FFI.
//! A v1 Android create transfers its duplicate exactly once. OwnedFd closes on
//! every failure path. AsyncFd uses nonblocking read/write, never Tokio's blocking
//! filesystem pool (a blocked TUN read cannot be reliably canceled there).
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::unix::AsyncFd,
    io::{AsyncRead, AsyncWrite, ReadBuf},
};
#[derive(Default)]
pub struct PacketCounts {
    pub failed: AtomicBool,
    pub read: AtomicU64,
    pub written: AtomicU64,
    pub v4: AtomicU64,
    pub v6: AtomicU64,
}
pub fn consume(raw: i64) -> io::Result<OwnedFd> {
    let raw: i32 = raw
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fd"))?;
    if raw < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative fd"));
    }
    // SAFETY: caller transferred a valid, uniquely owned duplicate by ABI contract.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: F_GETFD does not dereference memory and observes the owned fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
pub struct Device {
    fd: AsyncFd<OwnedFd>,
    counts: Arc<PacketCounts>,
    mtu: usize,
}
impl Device {
    pub fn new(fd: OwnedFd, mtu: usize, counts: Arc<PacketCounts>) -> io::Result<Self> {
        // SAFETY: fcntl only changes this owned duplicate's shared open description;
        // Android host agrees to nonblocking packet IO and retains original for close.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: OwnedFd is never exchanged or closed while registered; it
            // stays private in Device and unregisters before its unique drop.
            fd: unsafe { AsyncFd::register(fd) }?,
            counts,
            mtu,
        })
    }
}
impl AsyncRead for Device {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut ready = std::task::ready!(this.fd.poll_read_ready(cx))?;
            let len = buf.remaining().min(this.mtu);
            let dest = buf.initialize_unfilled_to(len);
            match ready.try_io(|fd| {
                // SAFETY: destination is writable for len and fd remains owned throughout.
                let n = unsafe { libc::read(fd.as_raw_fd(), dest.as_mut_ptr().cast(), len) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    if n == 0 {
                        this.counts.failed.store(true, Ordering::Release);
                    }
                    if n > 0 {
                        this.counts.read.fetch_add(1, Ordering::Relaxed);
                        match dest[0] >> 4 {
                            4 => {
                                this.counts.v4.fetch_add(1, Ordering::Relaxed);
                            }
                            6 => {
                                this.counts.v6.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => {
                    this.counts.failed.store(true, Ordering::Release);
                    return Poll::Ready(Err(e));
                }
                Err(_) => continue,
            }
        }
    }
}
impl AsyncWrite for Device {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() || buf.len() > this.mtu {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds MTU",
            )));
        }
        loop {
            let mut ready = std::task::ready!(this.fd.poll_write_ready(cx))?;
            match ready.try_io(|fd| {
                // SAFETY: buf readable for its full length; no pointers retained by write.
                let n = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    if n != buf.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "partial TUN packet",
                        )));
                    }
                    this.counts.written.fetch_add(1, Ordering::Relaxed);
                    return Poll::Ready(Ok(n));
                }
                Ok(Err(e)) => {
                    this.counts.failed.store(true, Ordering::Release);
                    return Poll::Ready(Err(e));
                }
                Err(_) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
