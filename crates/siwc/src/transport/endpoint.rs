//! Which URLs the transport sends to: the provider's two hosts, nothing else.

/// The only hosts a request goes to, always on port 443.
pub(crate) const HOSTS: [&str; 2] = ["auth.openai.com", "api.openai.com"];

/// A URL split into the host to connect to and the request target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Endpoint<'a> {
    pub(crate) host: &'static str,
    pub(crate) target: &'a str,
}

/// Splits `https://<host>/<path-and-query>` for one of [`HOSTS`]; any other
/// scheme, host, port, user info, a fragment or a byte outside visible ASCII
/// gives `None`.
pub(crate) fn parse(url: &str) -> Option<Endpoint<'_>> {
    let rest = url.strip_prefix("https://")?;
    let slash = rest.find('/')?;
    let authority = rest.get(..slash)?;
    let target = rest.get(slash..)?;
    let host = HOSTS.into_iter().find(|host| *host == authority)?;
    let clean = target
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'#');
    clean.then_some(Endpoint { host, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_hosts_are_accepted_with_their_path_and_query() {
        assert_eq!(
            parse("https://auth.openai.com/oauth/token"),
            Some(Endpoint {
                host: "auth.openai.com",
                target: "/oauth/token"
            })
        );
        assert_eq!(
            parse("https://api.openai.com/v1/models?a=b").map(|e| e.target),
            Some("/v1/models?a=b")
        );
        assert_eq!(
            parse("https://api.openai.com/").map(|e| e.host),
            Some("api.openai.com")
        );
    }

    #[test]
    fn other_hosts_ports_schemes_and_user_info_are_refused() {
        for url in [
            "http://auth.openai.com/oauth/token",
            "https://auth.openai.com:443/oauth/token",
            "https://auth.openai.com",
            "https://auth.openai.com?a=b",
            "https://user@auth.openai.com/",
            "https://auth.openai.com.example/",
            "https://AUTH.openai.com/",
            "https://openai.com/",
            "https://example.com/",
            "https://127.0.0.1/",
            "https://auth.openai.com/a b",
            "https://auth.openai.com/a\r\nX: y",
            "https://auth.openai.com/a#fragment",
            "https://auth.openai.com/\u{e4}",
            "",
        ] {
            assert_eq!(parse(url), None, "{url:?}");
        }
    }
}
