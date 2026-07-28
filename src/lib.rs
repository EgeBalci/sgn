//! SGN — a polymorphic binary encoder for x86/x64 shellcode.
//!
//! This is a Rust reimplementation of the original Go [SGN] tool. It encodes a
//! raw payload into a self-decoding, statistically-random-looking equivalent
//! using an additive feedback-loop (ADFL) cipher plus a per-run schema cipher
//! that hides the decoder stub itself. Instruction generation is done with the
//! [`iced-x86`] assembler instead of keystone.
//!
//! # Example
//! ```no_run
//! let mut enc = sgn::Encoder::new(64).unwrap();
//! let shellcode = std::fs::read("payload.bin").unwrap();
//! let encoded = enc.encode(&shellcode).unwrap();
//! println!("encoded {} bytes", encoded.len());
//! ```
//!
//! [SGN]: https://github.com/EgeBalci/sgn
//! [`iced-x86`]: https://docs.rs/iced-x86

pub mod cipher;
pub mod decoder;
pub mod encoder;
pub mod obfuscate;
pub mod registers;
pub mod util;

pub use cipher::{cipher_adfl, new_cipher_schema, schema_cipher, Schema, SchemaOp};
pub use encoder::{Encoder, Error};
