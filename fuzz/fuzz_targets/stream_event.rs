//! A chunk-size byte followed by an SSE frame or raw event payload classified by
//! `Refusal::from_event`, and decoded by `SseDecoder` whole and in pieces:
//! the events and the error must not depend on the split.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::plan::fuzz_event(data));
