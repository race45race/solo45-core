//! A tiny ZeroMQ SUB client: just enough ZMTP 3.0 (NULL security) to receive Bitcoin Core's zmqpubhashblock
//! notifications without libzmq. A port of Solo45's zmqsub.py.

use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const MORE: u8 = 0x01;
const LONG: u8 = 0x02;
const COMMAND: u8 = 0x04;
const MAX_FRAME: u64 = 1 << 20; // hashblock frames are 32 bytes; anything this big is not Bitcoin Core

pub struct ZmqSub {
    s: BufReader<TcpStream>,
}

impl ZmqSub {
    /// Connect to "host:port" and subscribe to `topic` (e.g. b"hashblock").
    pub async fn connect(addr: &str, topic: &[u8]) -> Result<ZmqSub> {
        let s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
        s.set_nodelay(true)?;
        let mut z = ZmqSub { s: BufReader::new(s) };
        tokio::time::timeout(Duration::from_secs(10), z.handshake(topic)).await??;
        Ok(z)
    }

    async fn handshake(&mut self, topic: &[u8]) -> Result<()> {
        // greeting: signature, version 3.0, NULL mechanism, not a server, filler (64 bytes)
        let mut g = vec![0xff];
        g.extend([0u8; 8]);
        g.push(0x7f);
        g.extend([3, 0]);
        let mut mech = b"NULL".to_vec();
        mech.resize(20, 0);
        g.extend(mech);
        g.push(0);
        g.extend([0u8; 31]);
        self.s.get_mut().write_all(&g).await?;
        let mut peer = [0u8; 64];
        self.s.read_exact(&mut peer).await?;
        if peer[0] != 0xff || peer[9] != 0x7f || peer[10] < 3 {
            bail!("the other side doesn't speak ZMTP 3");
        }
        let mut ready = b"\x05READY\x0bSocket-Type".to_vec();
        ready.extend(3u32.to_be_bytes());
        ready.extend(b"SUB");
        self.send(&ready, COMMAND).await?;
        let (flags, _) = self.frame().await?;
        if flags & COMMAND == 0 {
            bail!("expected the publisher's READY");
        }
        let mut sub = vec![1u8]; // subscribe (ZMTP 3.0 style: a message starting with 1)
        sub.extend_from_slice(topic);
        self.send(&sub, 0).await
    }

    async fn send(&mut self, body: &[u8], flags: u8) -> Result<()> {
        let mut out = Vec::with_capacity(body.len() + 9);
        if body.len() > 255 {
            out.push(flags | LONG);
            out.extend((body.len() as u64).to_be_bytes());
        } else {
            out.extend([flags, body.len() as u8]);
        }
        out.extend_from_slice(body);
        self.s.get_mut().write_all(&out).await?;
        Ok(())
    }

    async fn frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let flags = self.s.read_u8().await?;
        let size = if flags & LONG != 0 { self.s.read_u64().await? } else { self.s.read_u8().await? as u64 };
        if size > MAX_FRAME {
            bail!("ZMQ frame of {} bytes", size);
        }
        let mut body = vec![0u8; size as usize];
        self.s.read_exact(&mut body).await?;
        Ok((flags, body))
    }

    /// The next message as a list of frames, e.g. [b"hashblock", <32-byte hash>, <4-byte sequence>].
    pub async fn recv(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut parts = Vec::new();
        loop {
            let (flags, body) = self.frame().await?;
            if flags & COMMAND != 0 {
                continue; // a command such as PING, not part of a message
            }
            parts.push(body);
            if flags & MORE == 0 {
                return Ok(parts);
            }
        }
    }
}
