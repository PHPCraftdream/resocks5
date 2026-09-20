//! SOCKS5 handshake driven over an arbitrary async stream.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Performs SOCKS5 handshake over an existing stream.
pub async fn handshake_over_stream<S>(
    mut stream: S,
    target_addr: &str,
    auth: Option<(&str, &str)>,
) -> anyhow::Result<S>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if let Some((username, password)) = auth {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x02 {
            return Err(anyhow!(
                "[SOCKS5] Proxy does not support username/password authentication (received: {:02x})",
                response[1]
            ));
        }

        let uname = username.as_bytes();
        let passwd = password.as_bytes();
        if uname.len() > 255 || passwd.len() > 255 {
            return Err(anyhow!("[SOCKS5] Username or password too long"));
        }

        let mut auth_req = Vec::with_capacity(3 + uname.len() + passwd.len());
        auth_req.push(0x01);
        auth_req.push(uname.len() as u8);
        auth_req.extend_from_slice(uname);
        auth_req.push(passwd.len() as u8);
        auth_req.extend_from_slice(passwd);
        stream.write_all(&auth_req).await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
            return Err(anyhow!(
                "[SOCKS5] Authentication failed (status {:02x})",
                auth_resp[1]
            ));
        }
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(anyhow!(
                "[SOCKS5] Proxy does not support no-authentication method (received: {:02x})",
                response[1]
            ));
        }
    }

    let parsed = super::HostPort::parse(target_addr)
        .ok_or_else(|| anyhow!("[SOCKS5] Invalid target address format: {}", target_addr))?;
    let host = parsed.host;
    let port = parsed.port;
    let (atyp, addr_bytes) = if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        (0x01, ipv4.octets().to_vec())
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        (0x04, ipv6.octets().to_vec())
    } else {
        let domain = host.as_bytes();
        if domain.len() > 255 {
            return Err(anyhow!("[SOCKS5] Domain name too long"));
        }
        let mut v = vec![domain.len() as u8];
        v.extend_from_slice(domain);
        (0x03, v)
    };
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, atyp]);
    req.extend_from_slice(&addr_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 {
        return Err(anyhow!("[SOCKS5] Invalid proxy response version"));
    }
    if resp_header[1] != 0x00 {
        return Err(anyhow!(
            "[SOCKS5] CONNECT request error, error code: {:02x}",
            resp_header[1]
        ));
    }
    match resp_header[3] {
        0x01 => {
            stream.read_exact(&mut [0u8; 6]).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut skip = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            stream.read_exact(&mut [0u8; 18]).await?;
        }
        _ => return Err(anyhow!("[SOCKS5] Unknown address type in response")),
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::handshake_over_stream;

    /// Minimal no-auth SOCKS5 server stub over a duplex half: completes the
    /// greeting, captures the CONNECT request (head + address + port), then
    /// replies with success and the payload `ok`.
    async fn stub_server(mut upstream: tokio::io::DuplexStream) -> ([u8; 4], Vec<u8>) {
        let mut greeting = [0u8; 3];
        upstream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        upstream.write_all(&[0x05, 0x00]).await.unwrap();

        let mut head = [0u8; 4];
        upstream.read_exact(&mut head).await.unwrap();
        let mut addr = match head[3] {
            0x01 => {
                let mut b = [0u8; 6];
                upstream.read_exact(&mut b).await.unwrap();
                b.to_vec()
            }
            0x03 => {
                let mut len = [0u8; 1];
                upstream.read_exact(&mut len).await.unwrap();
                let mut b = vec![0u8; len[0] as usize + 2];
                upstream.read_exact(&mut b).await.unwrap();
                b
            }
            0x04 => {
                let mut b = [0u8; 18];
                upstream.read_exact(&mut b).await.unwrap();
                b.to_vec()
            }
            other => panic!("unexpected ATYP {other:02x}"),
        };
        addr.insert(0, head[3]);
        upstream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        upstream.write_all(b"ok").await.unwrap();
        (head, addr)
    }

    /// Drive the client side and return the captured request head and
    /// ATYP-prefixed address bytes, asserting the returned stream still
    /// carries the stub's `ok` payload.
    async fn exchange(target: &str) -> anyhow::Result<([u8; 4], Vec<u8>)> {
        let (mut client, upstream) = duplex(4096);
        let server = tokio::spawn(stub_server(upstream));
        let stream = handshake_over_stream(&mut client, target, None).await?;
        let mut payload = Vec::new();
        tokio::pin!(stream);
        stream.read_to_end(&mut payload).await?;
        assert_eq!(payload, b"ok");
        Ok(server.await.unwrap())
    }

    #[tokio::test]
    async fn bracketed_ipv6_uses_atyp4() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("[::1]:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(addr[0], 0x04);
        assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn bare_ipv6_uses_atyp4() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("::1:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn ipv4_uses_atyp1() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("1.2.3.4:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[tokio::test]
    async fn domain_uses_atyp3() {
        let (head, addr) =
            tokio::time::timeout(Duration::from_secs(5), exchange("example.com:443"))
                .await
                .expect("timed out")
                .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);
        assert_eq!(addr[0], 0x03);
        assert_eq!(&addr[1..12], b"example.com");
        assert_eq!(&addr[12..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn missing_port_is_rejected() {
        let result = tokio::time::timeout(Duration::from_secs(5), exchange("no-port-target"))
            .await
            .expect("timed out");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn full_ipv6_bracketed() {
        let (head, addr) =
            tokio::time::timeout(Duration::from_secs(5), exchange("[2001:db8::1]:443"))
                .await
                .expect("timed out")
                .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        let expected: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(&addr[1..17], &expected);
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }
}
