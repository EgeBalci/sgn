//! The [`Encoder`] type and the top-level encoding pipeline.

use crate::cipher::{cipher_adfl, new_cipher_schema, random_byte, schema_cipher};
use crate::decoder::{add_adfl_decoder, add_schema_decoder, DecoderError};
use crate::obfuscate::generate_garbage;
use rand::Rng;

/// x86 register-save prefix: `PUSHAD; PUSHFD`.
pub const X86_SAVE_PREFIX: &[u8] = &[0x60, 0x9c];
/// x86 register-restore suffix: `POPFD; POPAD`.
pub const X86_SAVE_SUFFIX: &[u8] = &[0x9d, 0x61];

/// x64 register-save prefix: push all general-purpose registers.
pub const X64_SAVE_PREFIX: &[u8] = &[
    0x50, 0x53, 0x51, 0x52, // PUSH RAX,RBX,RCX,RDX
    0x56, 0x57, 0x55, // PUSH RSI,RDI,RBP
    0x41, 0x50, 0x41, 0x51, // PUSH R8,R9
    0x41, 0x52, 0x41, 0x53, // PUSH R10,R11
    0x41, 0x54, 0x41, 0x55, // PUSH R12,R13
    0x41, 0x56, 0x41, 0x57, // PUSH R14,R15
];
/// x64 register-restore suffix: pop all general-purpose registers.
pub const X64_SAVE_SUFFIX: &[u8] = &[
    0x41, 0x5f, 0x41, 0x5e, // POP R15,R14
    0x41, 0x5d, 0x41, 0x5c, // POP R13,R12
    0x41, 0x5b, 0x41, 0x5a, // POP R11,R10
    0x41, 0x59, 0x41, 0x58, // POP R9,R8
    0x5d, 0x5f, 0x5e, // POP RBP,RDI,RSI
    0x5a, 0x59, 0x5b, 0x58, // POP RDX,RCX,RBX,RAX
];

/// Errors that can arise while encoding.
#[derive(Debug)]
pub enum Error {
    /// Architecture other than 32 or 64 was requested.
    InvalidArchitecture(u32),
    /// A decoder stub failed to assemble.
    Decoder(DecoderError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidArchitecture(a) => write!(f, "invalid architecture: {a}"),
            Error::Decoder(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<DecoderError> for Error {
    fn from(e: DecoderError) -> Self {
        Error::Decoder(e)
    }
}

impl From<iced_x86::IcedError> for Error {
    fn from(e: iced_x86::IcedError) -> Self {
        Error::Decoder(DecoderError::Iced(e))
    }
}

/// SGN polymorphic binary encoder. All knobs that steer encoding are public
/// fields, mirroring the original Go `Encoder` struct.
#[derive(Clone, Debug)]
pub struct Encoder {
    /// Target architecture: 32 or 64.
    pub architecture: u32,
    /// Maximum size, in bytes, of each generated garbage block.
    pub obfuscation_limit: i32,
    /// When true, the decoder stub is left in the clear (no schema layer).
    pub plain_decoder: bool,
    /// Current ADFL seed / key byte.
    pub seed: u8,
    /// Number of times to (recursively) encode the payload.
    pub encoding_count: u32,
    /// When true, wrap output so all registers are preserved.
    pub save_registers: bool,
}

impl Encoder {
    /// Creates a new encoder with default settings for `arch` (32 or 64).
    pub fn new(arch: u32) -> Result<Self, Error> {
        if arch != 32 && arch != 64 {
            return Err(Error::InvalidArchitecture(arch));
        }
        Ok(Encoder {
            architecture: arch,
            obfuscation_limit: 50,
            plain_decoder: false,
            seed: random_byte(&mut rand::thread_rng()),
            encoding_count: 1,
            save_registers: false,
        })
    }

    /// Sets the target architecture (32 or 64).
    pub fn set_architecture(&mut self, arch: u32) -> Result<(), Error> {
        if arch != 32 && arch != 64 {
            return Err(Error::InvalidArchitecture(arch));
        }
        self.architecture = arch;
        Ok(())
    }

    /// Register-save prefix bytes for the current architecture.
    pub fn save_prefix(&self) -> &'static [u8] {
        if self.architecture == 64 {
            X64_SAVE_PREFIX
        } else {
            X86_SAVE_PREFIX
        }
    }

    /// Register-restore suffix bytes for the current architecture.
    pub fn save_suffix(&self) -> &'static [u8] {
        if self.architecture == 64 {
            X64_SAVE_SUFFIX
        } else {
            X86_SAVE_SUFFIX
        }
    }

    /// Encodes `payload` into self-decoding polymorphic shellcode using the
    /// process-wide thread RNG. Convenience wrapper over [`Encoder::encode_with`].
    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = rand::thread_rng();
        self.encode_with(&mut rng, payload.to_vec())
    }

    /// Encodes `payload` using the supplied RNG. This is the core pipeline:
    ///
    /// 1. optionally append the register-restore suffix (safe mode);
    /// 2. prepend random garbage;
    /// 3. apply the ADFL cipher and prepend its decoder stub;
    /// 4. unless `plain_decoder`, schema-encrypt the stub and prepend a schema
    ///    decoder that reverses it at runtime;
    /// 5. recurse `encoding_count - 1` more times with fresh seeds;
    /// 6. optionally prepend the register-save prefix (safe mode).
    pub fn encode_with<R: Rng>(
        &mut self,
        rng: &mut R,
        mut payload: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let arch = self.architecture;

        if self.save_registers {
            payload.extend_from_slice(self.save_suffix());
        }

        // Garbage before the un-encoded payload.
        let mut garbage = generate_garbage(rng, arch, self.obfuscation_limit)?;
        garbage.extend_from_slice(&payload);
        payload = garbage;

        // ADFL cipher + decoder stub.
        cipher_adfl(&mut payload, self.seed);
        let ciphered_len = payload.len();
        let encoded = add_adfl_decoder(rng, arch, self.seed, payload)?;

        let mut result = if self.plain_decoder {
            encoded
        } else {
            // Garbage before the decoder stub, then schema-encrypt the header
            // (garbage + stub) region and wrap it in a schema decoder.
            let mut ep = generate_garbage(rng, arch, self.obfuscation_limit)?;
            ep.extend_from_slice(&encoded);

            let header_len = ep.len() - ciphered_len;
            let schema_size = (header_len / 4) + 1;
            ep.resize(ep.len().max(schema_size * 4), 0x90);

            let schema = new_cipher_schema(rng, schema_size);
            schema_cipher(&mut ep, &schema);
            add_schema_decoder(rng, arch, self.obfuscation_limit, ep, &schema)?
        };

        // Layer additional encoders.
        if self.encoding_count > 1 {
            self.encoding_count -= 1;
            self.seed = random_byte(rng);
            result = self.encode_with(rng, result)?;
        }

        if self.save_registers {
            let mut wrapped = self.save_prefix().to_vec();
            wrapped.extend_from_slice(&result);
            result = wrapped;
        }

        Ok(result)
    }
}
