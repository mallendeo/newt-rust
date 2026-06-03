//! Client data-plane backend selection. The kernel backend (transparent routing
//! via TUN + netlink) is Linux-only; the userspace backend (forwards via the
//! smoltcp engine) runs everywhere. Both present the same small interface to the
//! olm control loop.

use std::io;
use std::net::IpAddr;
use crate::config::{AccessMode, ClientRun};
use crate::olm::router::Cidr;
use crate::olm::userspace::{to_smol, UserspaceBackend};
#[cfg(target_os = "linux")]
use crate::olm::kernel::KernelBackend;

pub enum Backend {
    Userspace(UserspaceBackend),
    #[cfg(target_os = "linux")]
    Kernel(KernelBackend),
}

impl Backend {
    pub async fn new(cfg: &ClientRun, tunnel_ip: IpAddr) -> io::Result<Backend> {
        match cfg.access {
            AccessMode::Userspace => {
                if cfg.socks_port.is_some() {
                    return Err(io::Error::other(
                        "OLM_SOCKS_PORT is reserved and not yet implemented; use OLM_FORWARDS",
                    ));
                }
                let b = UserspaceBackend::new(to_smol(tunnel_ip), cfg.mtu, &cfg.forwards).await?;
                Ok(Backend::Userspace(b))
            }
            AccessMode::Kernel => {
                #[cfg(target_os = "linux")]
                {
                    Ok(Backend::Kernel(KernelBackend::new(&cfg.interface, tunnel_ip, cfg.mtu)?))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = tunnel_ip;
                    Err(io::Error::other(
                        "kernel TUN access mode is only supported on Linux; set OLM_ACCESS_MODE=userspace",
                    ))
                }
            }
        }
    }

    /// Plaintext IP packets produced by the host to encrypt and send.
    pub async fn drive(&mut self) -> io::Result<Vec<Vec<u8>>> {
        match self {
            Backend::Userspace(b) => b.drive().await,
            #[cfg(target_os = "linux")]
            Backend::Kernel(b) => b.drive().await,
        }
    }

    /// Deliver a decrypted IP packet to the host.
    pub async fn deliver_inbound(&mut self, pkt: &[u8]) -> io::Result<()> {
        match self {
            Backend::Userspace(b) => { b.deliver_inbound(pkt); Ok(()) }
            #[cfg(target_os = "linux")]
            Backend::Kernel(b) => b.deliver_inbound(pkt).await,
        }
    }

    /// Program OS routes for destination CIDRs (kernel backend only).
    pub fn add_routes(&mut self, cidrs: &[Cidr]) -> io::Result<()> {
        match self {
            Backend::Userspace(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Backend::Kernel(b) => b.add_routes(cidrs),
        }
    }
}
