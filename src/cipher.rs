//! The two ciphers that back SGN: the byte-wise ADFL (additive feedback loop)
//! cipher and the DWORD-wise schema cipher used to obfuscate the decoder stub.
//!
//! Both ciphers are written so that a matching, loop-free x86/x64 instruction
//! sequence (emitted in `decoder.rs`) reverses them at runtime. The schema
//! cipher here is expressed purely in terms of the CPU's native little-endian
//! DWORD view of memory, which is both simpler and clearer than the mixed
//! big/little-endian arithmetic in the original Go implementation while
//! producing an equivalent, self-consistent transform.

use rand::Rng;

/// A single step of the schema cipher. Each variant names the *decoder*
/// instruction that undoes it; the encryption side applies the inverse.
#[derive(Clone, Copy, Debug)]
pub enum SchemaOp {
    /// Decoder runs `XOR dword, key` (self-inverse).
    Xor(u32),
    /// Decoder runs `ADD dword, key`; encryption subtracts.
    Add(u32),
    /// Decoder runs `SUB dword, key`; encryption adds.
    Sub(u32),
    /// Decoder runs `ROL dword, n`; encryption rotates right.
    Rol(u8),
    /// Decoder runs `ROR dword, n`; encryption rotates left.
    Ror(u8),
    /// Decoder runs `NOT dword` (self-inverse).
    Not,
}

/// An ordered list of schema steps, one per 4-byte block.
pub type Schema = Vec<SchemaOp>;

/// Returns a random byte in the full `0..=255` range. The original Go
/// `GetRandomByte` used `rand.Intn(255)`, which could never yield 255; using
/// the whole byte range restores a bit of key entropy.
pub fn random_byte<R: Rng>(rng: &mut R) -> u8 {
    rng.gen()
}

/// Returns `true`/`false` with equal probability.
pub fn coin_flip<R: Rng>(rng: &mut R) -> bool {
    rng.gen()
}

/// Applies the ADFL cipher in place.
///
/// Walking from the last byte to the first, each byte is XORed with the current
/// seed and the seed for the next (earlier) byte becomes `(plaintext + seed) mod
/// 256`. Because the feedback uses the plaintext byte, the decoder must run in
/// the same last-to-first order, re-deriving the seed from each recovered byte —
/// which is exactly what the emitted ADFL stub does.
pub fn cipher_adfl(data: &mut [u8], mut seed: u8) {
    for byte in data.iter_mut().rev() {
        let plain = *byte;
        *byte = plain ^ seed;
        seed = plain.wrapping_add(seed);
    }
}

/// Builds a random schema of `count` steps with random operations and keys.
pub fn new_cipher_schema<R: Rng>(rng: &mut R, count: usize) -> Schema {
    (0..count)
        .map(|_| match rng.gen_range(0..6) {
            0 => SchemaOp::Xor(rng.gen()),
            1 => SchemaOp::Add(rng.gen()),
            2 => SchemaOp::Sub(rng.gen()),
            3 => SchemaOp::Rol(random_byte(rng)),
            4 => SchemaOp::Ror(random_byte(rng)),
            _ => SchemaOp::Not,
        })
        .collect()
}

/// Applies the schema cipher in place to the first `schema.len()` DWORD blocks
/// of `data`, treating each block as a native little-endian `u32`. Each step is
/// the inverse of the corresponding decoder instruction, so the runtime decoder
/// restores the original bytes block by block.
///
/// `data` must contain at least `schema.len() * 4` bytes.
pub fn schema_cipher(data: &mut [u8], schema: &Schema) {
    for (i, op) in schema.iter().enumerate() {
        let off = i * 4;
        let block = &mut data[off..off + 4];
        let v = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let out = match *op {
            SchemaOp::Xor(k) => v ^ k,
            // Decoder ADDs, so pre-subtract.
            SchemaOp::Add(k) => v.wrapping_sub(k),
            // Decoder SUBs, so pre-add.
            SchemaOp::Sub(k) => v.wrapping_add(k),
            // Decoder ROLs, so pre-rotate right (masked to 5 bits like the CPU).
            SchemaOp::Rol(n) => v.rotate_right((n & 31) as u32),
            // Decoder RORs, so pre-rotate left.
            SchemaOp::Ror(n) => v.rotate_left((n & 31) as u32),
            SchemaOp::Not => !v,
        };
        block.copy_from_slice(&out.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adfl_round_trips_against_a_forward_decoder() {
        // The decoder recovers bytes last-to-first: plain = cipher ^ seed,
        // seed' = plain + seed. Verify the cipher is inverted by that process.
        let original = b"\x90\x90\x90\xc3\x01\x02\x03\xff\x00".to_vec();
        let mut buf = original.clone();
        let seed = 0x7bu8;
        cipher_adfl(&mut buf, seed);

        let mut s = seed;
        for byte in buf.iter_mut().rev() {
            let plain = *byte ^ s;
            *byte = plain;
            s = plain.wrapping_add(s);
        }
        assert_eq!(buf, original);
    }

    #[test]
    fn schema_round_trips_against_decoder_ops() {
        let original: Vec<u8> = (0..40u8).collect();
        let mut buf = original.clone();
        let schema = vec![
            SchemaOp::Xor(0xdead_beef),
            SchemaOp::Add(0x0011_2233),
            SchemaOp::Sub(0x4455_6677),
            SchemaOp::Rol(5),
            SchemaOp::Ror(9),
            SchemaOp::Not,
        ];
        schema_cipher(&mut buf, &schema);

        // Emulate the decoder instructions block by block.
        for (i, op) in schema.iter().enumerate() {
            let off = i * 4;
            let block = &mut buf[off..off + 4];
            let v = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
            let out = match *op {
                SchemaOp::Xor(k) => v ^ k,
                SchemaOp::Add(k) => v.wrapping_add(k),
                SchemaOp::Sub(k) => v.wrapping_sub(k),
                SchemaOp::Rol(n) => v.rotate_left((n & 31) as u32),
                SchemaOp::Ror(n) => v.rotate_right((n & 31) as u32),
                SchemaOp::Not => !v,
            };
            block.copy_from_slice(&out.to_le_bytes());
        }
        assert_eq!(buf, original);
    }
}
