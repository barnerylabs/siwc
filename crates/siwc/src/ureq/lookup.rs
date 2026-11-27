//! ureq's system resolver, with a failed lookup reported like an empty one.

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

/// The default resolver. Its I/O errors come only from the system lookup,
/// whose kind says nothing stable about why a name has no address (an
/// unknown name is `Uncategorized` on Linux), so they become
/// [`ureq::Error::HostNotFound`], as when the lookup finds no address.
#[derive(Debug, Default)]
pub(super) struct Lookup(DefaultResolver);

impl Resolver for Lookup {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        self.0.resolve(uri, config, timeout).map_err(found_nothing)
    }
}

fn found_nothing(error: ureq::Error) -> ureq::Error {
    match error {
        ureq::Error::Io(_) => ureq::Error::HostNotFound,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::super::cause;
    use super::*;
    use crate::error::ErrorCause;

    #[test]
    fn a_failed_lookup_names_no_address_found_and_other_errors_pass() {
        // An unknown name, as the system lookup reports it on Linux.
        let failed = found_nothing(ureq::Error::Io(io::Error::other("no such host")));
        assert_eq!(
            cause::of(&failed),
            Some(ErrorCause::Io(io::ErrorKind::NotFound))
        );
        let timeout = found_nothing(ureq::Error::Timeout(ureq::Timeout::Resolve));
        assert_eq!(cause::of(&timeout), Some(ErrorCause::TimedOut));
    }
}
