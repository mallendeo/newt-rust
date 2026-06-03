//! Linux TUN device with async read/write via tokio's `AsyncFd`. No external
//! TUN crate: a single `TUNSETIFF` ioctl on /dev/net/tun, then the fd is driven
//! through the reactor. Packets are bare IP (IFF_NO_PI).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;

// TUNSETIFF = _IOW('T', 202, int). The ioctl request type is c_ulong on glibc
// but c_int on musl, so it is typed as libc::Ioctl. mips/powerpc/sparc encode the
// ioctl direction bits differently, giving a different request value there.
#[cfg(not(any(
    target_arch = "mips", target_arch = "mips32r6", target_arch = "mips64", target_arch = "mips64r6",
    target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64"
)))]
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
#[cfg(any(
    target_arch = "mips", target_arch = "mips32r6", target_arch = "mips64", target_arch = "mips64r6",
    target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64"
))]
const TUNSETIFF: libc::Ioctl = 0x8004_54ca_u32 as libc::Ioctl;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Tun {
    fd: AsyncFd<File>,
    name: String,
}

impl Tun {
    /// Open /dev/net/tun and create (or attach to) a TUN interface `name`.
    /// Returns the device with its kernel-assigned interface name.
    pub fn open(name: &str) -> io::Result<Tun> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;

        let mut req = IfReq { ifr_name: [0; 16], ifr_flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
        let bytes = name.as_bytes();
        let n = bytes.len().min(15);
        for i in 0..n {
            req.ifr_name[i] = bytes[i] as libc::c_char;
        }

        // SAFETY: req is a correctly-sized ifreq; the fd is open for the ioctl.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req as *mut _) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Recover the actual interface name the kernel assigned.
        let real: String = req
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();

        set_nonblocking(file.as_raw_fd())?;
        Ok(Tun { fd: AsyncFd::new(file)?, name: real })
    }

    pub fn name(&self) -> &str { &self.name }

    /// Read one IP packet from the interface.
    pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let mut f: &File = inner.get_ref();
                f.read(buf)
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet to the interface.
    pub async fn write_packet(&self, pkt: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let mut f: &File = inner.get_ref();
                f.write_all(pkt)?;
                Ok(())
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

fn set_nonblocking(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: fd is a valid open descriptor for the lifetime of this call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
