//! Bounded growth of the buffers that hold a response: the bodies the HTTP
//! transports collect and the event the SSE decoder puts together.

use zeroize::Zeroizing;

/// Makes room for `more` bytes within `limit`. On growth, the old buffer
/// is wiped on drop instead of being freed by a reallocation.
pub(crate) fn reserve(body: &mut Zeroizing<Vec<u8>>, more: usize, limit: usize) -> Option<()> {
    let needed = body.len().checked_add(more)?;
    if needed > limit {
        return None;
    }
    if needed > body.capacity() {
        let capacity = needed.max(body.capacity().saturating_mul(2)).min(limit);
        let mut larger = Zeroizing::new(Vec::new());
        larger.try_reserve_exact(capacity).ok()?;
        larger.extend_from_slice(body);
        *body = larger;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_preserves_the_body_and_refuses_to_exceed_the_limit() {
        let mut body = Zeroizing::new(b"ab".to_vec());
        let original = body.as_ptr();
        reserve(&mut body, 3, 5).unwrap();
        let grown = body.as_ptr();
        assert_ne!(original, grown);
        reserve(&mut body, 3, 5).unwrap();
        assert_eq!(body.as_ptr(), grown);
        body.extend_from_slice(b"cde");
        assert!(reserve(&mut body, 1, 5).is_none());
        assert!(reserve(&mut body, usize::MAX, 5).is_none());
        assert_eq!(&body[..], b"abcde");
    }
}
