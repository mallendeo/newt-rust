use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Channels owned by the tunnel loop for one bridged TCP connection.
pub struct Conn {
    /// smoltcp -> target: loop pushes bytes read from the smoltcp socket.
    pub to_target: mpsc::Sender<Vec<u8>>,
    /// target -> smoltcp: loop drains bytes to write into the smoltcp socket.
    pub from_target: mpsc::Receiver<Vec<u8>>,
}

/// Spawn the task that owns the real TCP connection to `target`.
pub fn spawn_tcp(target: String) -> Conn {
    let (to_target_tx, mut to_target_rx) = mpsc::channel::<Vec<u8>>(16);
    let (from_target_tx, from_target_rx) = mpsc::channel::<Vec<u8>>(16);

    tokio::spawn(async move {
        let mut stream = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => { crate::debug!("target connect {target} failed: {e}"); return; }
        };
        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                msg = to_target_rx.recv() => match msg {
                    Some(data) => { if stream.write_all(&data).await.is_err() { break; } }
                    None => break, // loop dropped sender => connection closed
                },
                n = stream.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if from_target_tx.send(buf[..n].to_vec()).await.is_err() { break; } }
                },
            }
        }
        let _ = stream.shutdown().await;
    });

    Conn { to_target: to_target_tx, from_target: from_target_rx }
}
