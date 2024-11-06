//! The `Keccak` hash functions.

use super::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState};
#[cfg(target_os = "zkvm")]
extern crate alloc;
#[cfg(target_os = "zkvm")]
use alloc::{vec, vec::Vec};
/// The `Keccak` hash functions defined in [`Keccak SHA3 submission`].
///
/// # Usage
///
/// ```toml
/// [dependencies]
/// tiny-keccak = { version = "2.0.0", features = ["keccak"] }
/// ```
///
/// [`Keccak SHA3 submission`]: https://keccak.team/files/Keccak-submission-3.pdf
#[derive(Clone)]
pub struct Keccak {
    state: KeccakState<KeccakF>,
    #[cfg(target_os = "zkvm")]
    raw_data: Vec<u8>,
    #[cfg(target_os = "zkvm")]
    slow_path: bool,
}

impl Keccak {
    const DELIM: u8 = 0x01;

    /// Creates  new [`Keccak`] hasher with a security level of 224 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v224() -> Keccak {
        Keccak::new(224)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Keccak {
        Keccak::new(256)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 384 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v384() -> Keccak {
        Keccak::new(384)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 512 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v512() -> Keccak {
        Keccak::new(512)
    }

    fn new(bits: usize) -> Keccak {
        Keccak {
            state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
            #[cfg(target_os = "zkvm")]
            raw_data: vec![],
            #[cfg(target_os = "zkvm")]
            slow_path: false,
        }
    }
}

impl Hasher for Keccak {
    /// Absorb additional input. Can be called multiple times.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let mut keccak = Keccak::v256();
    /// keccak.update(b"hello");
    /// keccak.update(b" world");
    /// # }
    /// ```
    #[cfg(not(target_os = "zkvm"))]
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    #[cfg(target_os = "zkvm")]
    fn update(&mut self, input: &[u8]) {
        if !self.slow_path {
            if self.raw_data.len() + input.len() > 100_000 {
                self.slow_path = true;
                self.state.update(&self.raw_data);
            }
            else {
                self.raw_data.extend_from_slice(input);
            }
        }

        if self.slow_path {
            self.state.update(input);
        }
    }

    /// Pad and squeeze the state to the output.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let keccak = Keccak::v256();
    /// # let mut output = [0u8; 32];
    /// keccak.finalize(&mut output);
    /// # }
    /// #
    /// ```
    #[cfg(not(target_os = "zkvm"))]
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }

    #[cfg(target_os = "zkvm")]
    fn finalize(self, output: &mut [u8]) {
        if self.slow_path {
            self.state.finalize(output);
        } else {
            output.clone_from_slice(&risc0_zkvm::guest::env::keccak_digest(&self.raw_data, Self::DELIM).unwrap().as_mut_slice());
        }
    }
}
