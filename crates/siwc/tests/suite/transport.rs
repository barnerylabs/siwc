//! The two seams to the outside: what sends requests and what tells the time.

use std::sync::Arc;

use siwc::protocol::{HttpRequest, HttpResponse, Jwks};
use siwc::{Clock, Error, ErrorKind, Transport, UnixTime};

use crate::support::provider::User;
use crate::support::{NOW, World};

/// A network that is down.
#[derive(Debug)]
struct Offline;

impl Transport for Offline {
    fn send(&self, _request: &HttpRequest) -> Result<HttpResponse, Error> {
        Err(Error::transport_unavailable())
    }
}

#[test]
fn a_sign_in_runs_over_any_transport() {
    let world = World::new();
    let transport: &dyn Transport = &world.provider;

    let exchange = world.authorized(&User::alex());
    let keys = Jwks::from_response(&transport.send(&Jwks::request()).unwrap()).unwrap();
    let response = transport.send(&exchange.request()).unwrap();
    let signed_in = exchange
        .response(response, world.now())
        .unwrap()
        .verify(&keys, world.now())
        .unwrap();

    assert_eq!(signed_in.identity().email(), Some("alex@example.com"));
}

#[test]
fn a_transport_without_an_answer_reports_a_temporary_failure() {
    let error = Offline.send(&Jwks::request()).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert!(error.is_temporary());
    assert_eq!(error.provider_code(), None);
}

#[test]
fn a_shared_transport_is_a_transport() {
    let world = World::new();
    let shared: Arc<dyn Transport> = Arc::new(world.provider);

    let response = Transport::send(&shared, &Jwks::request()).unwrap();

    assert_eq!(response.status(), 200);
}

#[test]
fn a_clock_tells_the_time_it_was_given() {
    #[derive(Debug)]
    struct Frozen;

    impl Clock for Frozen {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(NOW)
        }
    }

    let clock: &dyn Clock = &Frozen;
    assert_eq!(clock.now().as_secs(), NOW);
}
