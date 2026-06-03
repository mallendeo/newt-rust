use std::collections::VecDeque;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// A smoltcp device with no link layer. `rx` holds decrypted inbound IP packets
/// (filled by the tunnel loop before each poll); packets smoltcp transmits are
/// pushed into `tx` for the tunnel loop to encapsulate after each poll.
pub struct VirtualDevice {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: usize) -> Self {
        VirtualDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu }
    }
}

pub struct Rx(Vec<u8>);
pub struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R { f(&self.0) }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Rx, Tx<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((Rx(pkt), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _t: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

pub struct Stack {
    pub device: VirtualDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
}

impl Stack {
    pub fn new(tunnel_ip: IpAddress, mtu: usize, now: Instant) -> Self {
        let mut device = VirtualDevice::new(mtu);
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            let prefix = match tunnel_ip { IpAddress::Ipv4(_) => 32, IpAddress::Ipv6(_) => 128 };
            addrs.push(IpCidr::new(tunnel_ip, prefix)).ok();
        });
        Stack { device, iface, sockets: SocketSet::new(Vec::new()) }
    }

    /// Drive the stack once. Returns outbound IP packets smoltcp produced.
    pub fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.device.tx.drain(..).collect()
    }

    /// Install default routes so the stack can originate connections to
    /// off-link destinations (used by the client/olm userspace backend). The
    /// device has no link layer, so the gateway is only a routing placeholder;
    /// the emitted IP packet is demultiplexed downstream by destination.
    pub fn add_default_routes(&mut self, gw4: smoltcp::wire::Ipv4Address, gw6: smoltcp::wire::Ipv6Address) {
        self.iface.routes_mut().add_default_ipv4_route(gw4).ok();
        self.iface.routes_mut().add_default_ipv6_route(gw6).ok();
    }

    /// Originate a connection from `local_port` to `remote` on a TCP socket.
    pub fn connect(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        remote: (smoltcp::wire::IpAddress, u16),
        local_port: u16,
    ) -> Result<(), smoltcp::socket::tcp::ConnectError> {
        let cx = self.iface.context();
        self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle).connect(cx, remote, local_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rx_token_yields_packet_and_tx_queues() {
        let mut d = VirtualDevice::new(1280);
        d.rx.push_back(vec![1, 2, 3]);
        let (rx, tx) = d.receive(Instant::ZERO).unwrap();
        let got = rx.consume(|b| b.to_vec());
        assert_eq!(got, vec![1, 2, 3]);
        tx.consume(4, |b| { b.copy_from_slice(&[9, 9, 9, 9]); });
        assert_eq!(d.tx.pop_front().unwrap(), vec![9, 9, 9, 9]);
    }
}
