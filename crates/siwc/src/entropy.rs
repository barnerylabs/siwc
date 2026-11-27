//! Where random bytes come from.

use std::fmt;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::Error;

/// A source of unpredictable bytes for `state`, `nonce`, the PKCE verifier
/// and the host ID.
///
/// The `testing` feature exposes this trait so tests can supply fixed bytes.
/// Production code uses [`OsEntropy`].
///
/// **Compatibility:** a release that is not a breaking one adds no required
/// method or supertrait and keeps the trait usable as `dyn Entropy`; a new
/// method, such as a fill that knows what the bytes are for, comes with a
/// default that calls [`fill`](Self::fill).
#[cfg_attr(
    not(feature = "testing"),
    expect(unreachable_pub, reason = "the trait is only exported with testing")
)]
pub trait Entropy: Send + Sync {
    /// Fills `bytes` completely or fails without partial output being used.
    ///
    /// # Errors
    ///
    /// Returns an error when no random bytes are available.
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error>;
}

impl<T: Entropy + ?Sized> Entropy for &T {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        (**self).fill(bytes)
    }
}

impl<T: Entropy + ?Sized> Entropy for Arc<T> {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        (**self).fill(bytes)
    }
}

impl<T: Entropy + ?Sized> Entropy for Box<T> {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        (**self).fill(bytes)
    }
}

/// A stateless handle to the operating system's random source.
///
/// ```
/// let host = siwc::HostId::generate(&siwc::OsEntropy)?;
/// assert!(host.as_str().starts_with("urn:uuid:"));
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(
    not(feature = "testing"),
    doc = "\n```compile_fail,E0432\nuse siwc::Entropy;\n```"
)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        SystemRandom::new()
            .fill(bytes)
            .map_err(|_| Error::entropy_unavailable())
    }
}

impl fmt::Debug for OsEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OsEntropy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_arc_and_debug_work_for_os_entropy() {
        assert_eq!(format!("{OsEntropy:?}"), "OsEntropy");
        let boxed: Box<dyn Entropy> = Box::new(OsEntropy);
        let shared: Arc<dyn Entropy> = Arc::new(OsEntropy);
        let mut a = [0_u8; 8];
        let mut b = [0_u8; 8];
        let mut c = [0_u8; 8];
        let borrowed: &dyn Entropy = &OsEntropy;
        boxed.fill(&mut a).unwrap();
        shared.fill(&mut b).unwrap();
        (&borrowed).fill(&mut c).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
