#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Socks5,
    Http,
    Https,
}
