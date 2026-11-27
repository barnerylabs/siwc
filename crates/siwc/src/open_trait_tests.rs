//! Compile-time guards for the extension policy of the open traits:
//! each stays usable as a trait object, and the crate's
//! forwarding impls keep the wrapped forms usable where a trait is expected.

use std::sync::Arc;

use crate::store::{SealingKey, Store};
use crate::{Clock, Transport};

fn transport<T: Transport + ?Sized>() {}
fn store<T: Store + ?Sized>() {}
fn sealing_key<T: SealingKey + ?Sized>() {}
fn clock<T: Clock + ?Sized>() {}

#[test]
fn open_traits_stay_usable_as_trait_objects_and_through_their_wrappers() {
    transport::<dyn Transport>();
    transport::<Box<dyn Transport>>();
    transport::<Arc<dyn Transport>>();

    store::<dyn Store>();
    store::<Box<dyn Store>>();
    store::<Arc<dyn Store>>();

    sealing_key::<dyn SealingKey>();
    sealing_key::<Box<dyn SealingKey>>();
    sealing_key::<Arc<dyn SealingKey>>();

    clock::<dyn Clock>();
    clock::<Box<dyn Clock>>();
    clock::<Arc<dyn Clock>>();
}

#[cfg(feature = "testing")]
#[test]
fn entropy_stays_usable_as_a_trait_object_and_through_its_wrappers() {
    use crate::Entropy;

    fn entropy<T: Entropy + ?Sized>() {}

    entropy::<dyn Entropy>();
    entropy::<&dyn Entropy>();
    entropy::<Box<dyn Entropy>>();
    entropy::<Arc<dyn Entropy>>();
}
