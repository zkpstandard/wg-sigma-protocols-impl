//! A reference implementation of the ZKProof standard for Sigma Protocols.
//! The current version of the standard is available here <https://github.com/zkpstandard/wg-sigma-protocols/tree/build>

#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]

/// Length of a label in bytes
pub const LABEL_LENGTH: usize = 32;

/// Length of a challenge in bytes
pub const CHALLENGE_LENGTH: usize = 32;

/// Domain separator for the hash functions
pub const DOMSEP: &[u8] = b"zkpstd/sigma/0.1";

/// Type alias for a challenge
pub type Challenge = [u8; CHALLENGE_LENGTH];

mod interactive_proofs;
pub use interactive_proofs::SigmaProtocol;

mod nizk_proofs;
pub use nizk_proofs::{BatchableProof, ShortProof, NIZK};

/// Module defining the set of all supported hash functions
mod hash_registry;
pub use hash_registry::HashFunction;

/// Concrete implementations of known Sigma protocols.
pub mod protocols;

// pub enum ComposedSigmaProtocol {
//     ANDComposition,
//     ORComposition,
// }

/// An error type for failures in sigma protocols
pub enum SigmaError {
    /// An error to signify that verification has failed
    VerificationFailed,
}
