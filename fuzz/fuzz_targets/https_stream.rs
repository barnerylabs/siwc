//! An HTTP/1.x response whose body the built-in `https` transport streams:
//! the decoded body must not depend on how the bytes arrive or on how many
//! the reader asks for, and must equal the body read whole.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::https::fuzz_stream(data));
