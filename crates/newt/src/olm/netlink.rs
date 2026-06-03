//! Minimal rtnetlink over a raw AF_NETLINK socket: bring a link up, assign an
//! address, and add routes. No external crate, so the static drop-and-run build
//! keeps no runtime dependency on iproute2/busybox `ip`.

use std::io;
use std::net::IpAddr;
use std::os::unix::io::{FromRawFd, OwnedFd, AsRawFd};

// message types
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
// header flags
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
// attribute types
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
// routing constants
const RT_TABLE_MAIN: u8 = 254;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;
const IFF_UP: u32 = 1;

pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Netlink> {
        // SAFETY: standard socket(2); the returned fd is owned below.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh, owned, valid descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Netlink { fd, seq: 1 })
    }

    /// Look up an interface index by name.
    pub fn if_index(name: &str) -> io::Result<u32> {
        let cname = std::ffi::CString::new(name).map_err(|_| io::Error::other("bad ifname"))?;
        // SAFETY: cname is a valid NUL-terminated C string.
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(idx)
    }

    pub fn set_mtu(&mut self, ifindex: u32, mtu: u32) -> io::Result<()> {
        const IFLA_MTU: u16 = 4;
        let mut payload = Vec::new();
        payload.push(libc::AF_UNSPEC as u8);
        payload.push(0);
        payload.extend_from_slice(&0u16.to_ne_bytes()); // type
        payload.extend_from_slice(&(ifindex as i32).to_ne_bytes());
        payload.extend_from_slice(&0u32.to_ne_bytes()); // flags
        payload.extend_from_slice(&0u32.to_ne_bytes()); // change
        push_attr(&mut payload, IFLA_MTU, &mtu.to_ne_bytes());
        self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, payload)
    }

    pub fn link_up(&mut self, ifindex: u32) -> io::Result<()> {
        // ifinfomsg: family,pad,type,index,flags,change
        let mut payload = Vec::new();
        payload.push(libc::AF_UNSPEC as u8);
        payload.push(0);
        payload.extend_from_slice(&0u16.to_ne_bytes()); // type
        payload.extend_from_slice(&(ifindex as i32).to_ne_bytes());
        payload.extend_from_slice(&IFF_UP.to_ne_bytes()); // flags
        payload.extend_from_slice(&IFF_UP.to_ne_bytes()); // change
        self.request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, payload)
    }

    pub fn add_addr(&mut self, ifindex: u32, ip: IpAddr, prefix: u8) -> io::Result<()> {
        let (family, addr) = fam_bytes(ip);
        // ifaddrmsg: family,prefixlen,flags,scope,index
        let mut payload = vec![family, prefix, 0, RT_SCOPE_UNIVERSE];
        payload.extend_from_slice(&ifindex.to_ne_bytes());
        push_attr(&mut payload, IFA_LOCAL, &addr);
        push_attr(&mut payload, IFA_ADDRESS, &addr);
        self.request(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, payload)
    }

    pub fn add_route(&mut self, ifindex: u32, dst: IpAddr, prefix: u8) -> io::Result<()> {
        let (family, addr) = fam_bytes(dst);
        // rtmsg: family,dst_len,src_len,tos,table,protocol,scope,type,flags
        let mut payload = vec![
            family, prefix, 0, 0,
            RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_LINK, RTN_UNICAST,
        ];
        payload.extend_from_slice(&0u32.to_ne_bytes()); // flags
        push_attr(&mut payload, RTA_DST, &addr);
        push_attr(&mut payload, RTA_OIF, &ifindex.to_ne_bytes());
        self.request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, payload)
    }

    /// Send one request and wait for its ACK, mapping a netlink error to io::Error.
    fn request(&mut self, msg_type: u16, flags: u16, payload: Vec<u8>) -> io::Result<()> {
        let seq = self.seq;
        self.seq += 1;
        let total = 16 + payload.len();
        let mut msg = Vec::with_capacity(align4(total));
        msg.extend_from_slice(&(total as u32).to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel fills)
        msg.extend_from_slice(&payload);

        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;

        // SAFETY: msg/dst are valid for the duration of the call.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        self.read_ack()
    }

    fn read_ack(&self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        // SAFETY: buf is valid and sized; recv writes at most buf.len() bytes.
        let n = unsafe {
            libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 20 {
            return Err(io::Error::other("short netlink ack"));
        }
        // nlmsghdr (16) then NLMSG_ERROR body: i32 error, then original header.
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        const NLMSG_ERROR: u16 = 2;
        if msg_type == NLMSG_ERROR {
            let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if err == 0 {
                return Ok(()); // ACK
            }
            return Err(io::Error::from_raw_os_error(-err));
        }
        Ok(())
    }
}

fn fam_bytes(ip: IpAddr) -> (u8, Vec<u8>) {
    match ip {
        IpAddr::V4(a) => (libc::AF_INET as u8, a.octets().to_vec()),
        IpAddr::V6(a) => (libc::AF_INET6 as u8, a.octets().to_vec()),
    }
}

fn push_attr(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    let len = 4 + data.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn align4(n: usize) -> usize { (n + 3) & !3 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_is_padded_to_4() {
        let mut b = Vec::new();
        push_attr(&mut b, RTA_OIF, &7u32.to_ne_bytes());
        assert_eq!(b.len(), 8); // 4 header + 4 data
        let mut b = Vec::new();
        push_attr(&mut b, RTA_DST, &[10, 0, 0, 0]);
        assert_eq!(b.len(), 8);
        let mut b = Vec::new();
        push_attr(&mut b, IFA_LOCAL, &[1, 2, 3, 4, 5, 6]); // 6 bytes -> pad to 8 + 4 hdr = 12
        assert_eq!(b.len(), 12);
    }
}
