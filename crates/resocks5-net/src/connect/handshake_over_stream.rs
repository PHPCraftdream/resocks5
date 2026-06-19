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

    let parts: Vec<&str> = target_addr.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "[SOCKS5] Invalid target address format: {}",
            target_addr
        ));
    }
    let port: u16 = parts[0].parse()?;
    let host = parts[1];
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
