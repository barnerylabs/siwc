//! The same explicit proxy URL syntax as the `Https` transport.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, ErrorKind};

pub(super) fn parse_proxy(url: &str) -> Result<ureq::Proxy, Error> {
    let invalid = || Error::new(ErrorKind::InvalidInput, "the proxy URL is invalid");
    if url.is_empty() || !url.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid());
    }
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(invalid)?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return Err(invalid());
    }
    let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
    if !valid_host(host) || !valid_port(port) {
        return Err(invalid());
    }
    let proxy = ureq::Proxy::new(url).map_err(|_| invalid())?;
    if proxy.username().is_some() || proxy.password().is_some() {
        return Err(invalid());
    }
    Ok(proxy)
}

fn valid_host(host: &str) -> bool {
    if let Some(address) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return address.parse::<Ipv6Addr>().is_ok();
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && host
            .rsplit_once('.')
            .map_or(host, |(_, last)| last)
            .bytes()
            .any(|byte| byte.is_ascii_alphabetic())
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}
