//! Deterministic stand-ins for randomness.

use std::sync::atomic::{AtomicU64, Ordering};

use siwc::{Entropy, Error};

/// SplitMix64: a small generator for reproducible test inputs.
pub struct Generator(u64);

impl Generator {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    /// `valid` after one to three edits: a byte replaced, removed or
    /// inserted from `alphabet`, the rest cut off, or the rest repeated.
    pub fn mangle(&mut self, valid: &[u8], alphabet: &[u8]) -> Vec<u8> {
        let mut bytes = valid.to_vec();
        for _ in 0..=self.below(3) {
            if bytes.is_empty() {
                break;
            }
            let at = self.below(bytes.len());
            match self.below(5) {
                0 => bytes[at] = self.next_u64() as u8,
                1 => drop(bytes.remove(at)),
                2 => bytes.insert(at, self.pick(alphabet)),
                3 => bytes.truncate(at),
                _ => {
                    let copy = bytes[at..].to_vec();
                    bytes.extend_from_slice(&copy);
                }
            }
        }
        bytes
    }
}

/// Entropy that is different on every call and the same on every run.
pub struct Seeded(AtomicU64);

impl Seeded {
    pub fn new(seed: u64) -> Self {
        Self(AtomicU64::new(seed))
    }
}

impl Entropy for Seeded {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        let mut generator = Generator::new(self.0.fetch_add(1, Ordering::Relaxed));
        for byte in bytes {
            *byte = generator.next_u64() as u8;
        }
        Ok(())
    }
}
