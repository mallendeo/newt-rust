//! Linux kernel-TUN client backend: a real TUN interface plus rtnetlink routes.
//! The host kernel forwards traffic for remote subnets into the tunnel, so
//! access is transparent (no per-port forwards). Needs /dev/net/tun and
//! CAP_NET_ADMIN.

use std::io;
use std::net::IpAddr;
use crate::olm::netlink::Netlink;
use crate::olm::router::Cidr;
use crate::olm::tun::Tun;

pub struct KernelBackend {
    tun: Tun,
    nl: Netlink,
    ifindex: u32,
    buf: Vec<u8>,
}

impl KernelBackend {
    /// Open the TUN, assign `tunnel_ip`, set the MTU and bring the link up.
    pub fn new(interface: &str, tunnel_ip: IpAddr, mtu: usize) -> io::Result<Self> {
        let tun = Tun::open(interface)?;
        let name = tun.name().to_string();
        let ifindex = Netlink::if_index(&name)?;
        let mut nl = Netlink::open()?;
        nl.set_mtu(ifindex, mtu as u32)?;
        nl.add_addr(ifindex, tunnel_ip, host_prefix(tunnel_ip))?;
        nl.link_up(ifindex)?;
        crate::info!("tun {name} up, ip {tunnel_ip}, mtu {mtu}");
        Ok(KernelBackend { tun, nl, ifindex, buf: vec![0u8; mtu.max(1500) + 64] })
    }

    /// Program OS routes for the given destination CIDRs into the TUN.
    pub fn add_routes(&mut self, cidrs: &[Cidr]) -> io::Result<()> {
        for c in cidrs {
            let (net, prefix) = c.parts();
            if let Err(e) = self.nl.add_route(self.ifindex, net, prefix) {
                crate::warn!("add route {net}/{prefix} failed: {e}");
            }
        }
        Ok(())
    }

    pub async fn drive(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let n = self.tun.read_packet(&mut self.buf).await?;
        if n == 0 { return Ok(Vec::new()); }
        Ok(vec![self.buf[..n].to_vec()])
    }

    pub async fn deliver_inbound(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.tun.write_packet(pkt).await
    }
}

/// Host route prefix for an interface address (/32 v4, /128 v6).
fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
