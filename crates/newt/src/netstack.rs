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
