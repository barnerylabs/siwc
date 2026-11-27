//! Entry points built only for the cargo-fuzz response harnesses.

use crate::protocol::HttpResponse;
use crate::time::UnixTime;

use super::Credentials;

impl Credentials {
    /// Reads the renewal answer and its refresh time for the cargo-fuzz harness.
    #[doc(hidden)]
    pub fn fuzz_refresh_response(&self, response: HttpResponse, now: UnixTime) {
        if let Ok(renewed) = self.refreshed(response, now) {
            let _parsed = renewed.earliest_refresh_time();
        }
    }

    /// Reads the revocation answer for the cargo-fuzz harness.
    #[doc(hidden)]
    pub fn fuzz_revocation_response(&self, response: &HttpResponse) {
        let _parsed = self.revocation_confirmed(response);
    }
}
