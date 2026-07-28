//! General-purpose register pools and random selection.
//!
//! Instead of the string-based register tables the original Go implementation
//! fed to keystone, we work directly with `iced-x86`'s strongly-typed register
//! constants. A register is identified by its index into the per-architecture
//! pool; helper functions map an index to the concrete `AsmRegister{8,32,64}`
//! constant needed by the assembler API.
//!
//! Pool ordering (index -> register) is identical for both architectures for
//! the first six entries, which lets us refer to "the RCX/ECX slot" as index
//! [`RCX_INDEX`] regardless of bitness.

use iced_x86::code_asm::*;
use rand::Rng;

/// Number of registers in the 64-bit pool (RAX..R15, excluding RSP/RBP).
pub const N64: usize = 14;
/// Number of registers in the 32-bit pool (EAX, EBX, ECX, EDX, ESI, EDI).
pub const N32: usize = 6;
/// Index of the (R/E)CX slot, reserved as the decoder loop counter.
pub const RCX_INDEX: usize = 2;

/// Size of the general-purpose register pool for the given architecture.
pub fn pool_size(arch: u32) -> usize {
    if arch == 64 {
        N64
    } else {
        N32
    }
}

/// 64-bit register constant for pool index `i`.
pub fn reg64(i: usize) -> AsmRegister64 {
    match i {
        0 => rax,
        1 => rbx,
        2 => rcx,
        3 => rdx,
        4 => rsi,
        5 => rdi,
        6 => r8,
        7 => r9,
        8 => r10,
        9 => r11,
        10 => r12,
        11 => r13,
        12 => r14,
        _ => r15,
    }
}

/// 8-bit (low byte) register constant for 64-bit pool index `i`.
/// Every 64-bit GP register has an addressable low byte.
pub fn low64(i: usize) -> AsmRegister8 {
    match i {
        0 => al,
        1 => bl,
        2 => cl,
        3 => dl,
        4 => sil,
        5 => dil,
        6 => r8b,
        7 => r9b,
        8 => r10b,
        9 => r11b,
        10 => r12b,
        11 => r13b,
        12 => r14b,
        _ => r15b,
    }
}

/// 32-bit register constant for pool index `i`.
pub fn reg32(i: usize) -> AsmRegister32 {
    match i {
        0 => eax,
        1 => ebx,
        2 => ecx,
        3 => edx,
        4 => esi,
        _ => edi,
    }
}

/// 8-bit (low byte) register constant for 32-bit pool index `i`, if one exists.
/// In 32-bit mode only EAX/EBX/ECX/EDX expose a low byte (AL/BL/CL/DL);
/// ESI/EDI do not, so those indices return `None`.
pub fn low32(i: usize) -> Option<AsmRegister8> {
    match i {
        0 => Some(al),
        1 => Some(bl),
        2 => Some(cl),
        3 => Some(dl),
        _ => None,
    }
}

/// Returns a random pool index for `arch`, optionally excluding a set of
/// indices. Returns `None` if every index is excluded.
fn random_index<R: Rng>(rng: &mut R, arch: u32, exclude: &[usize]) -> Option<usize> {
    let n = pool_size(arch);
    let candidates: Vec<usize> = (0..n).filter(|i| !exclude.contains(i)).collect();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates[rng.gen_range(0..candidates.len())])
    }
}

/// Picks any full-size GP register index (used for value-preserving garbage).
pub fn random_gp<R: Rng>(rng: &mut R, arch: u32) -> usize {
    rng.gen_range(0..pool_size(arch))
}

/// Picks a full-size register usable as the decoder's payload-pointer base,
/// excluding the loop-counter slot (RCX/ECX).
pub fn random_base<R: Rng>(rng: &mut R, arch: u32) -> usize {
    random_index(rng, arch, &[RCX_INDEX]).expect("register pool exhausted")
}

/// Picks a low-byte register index for the ADFL key register, distinct from the
/// payload-pointer register `base_idx` and from the counter slot (CL). For
/// 32-bit mode the index is additionally constrained to registers that have an
/// addressable low byte.
pub fn random_low<R: Rng>(rng: &mut R, arch: u32, base_idx: usize) -> Option<usize> {
    let n = pool_size(arch);
    let candidates: Vec<usize> = (0..n)
        .filter(|&i| i != base_idx && i != RCX_INDEX)
        .filter(|&i| arch == 64 || low32(i).is_some())
        .collect();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates[rng.gen_range(0..candidates.len())])
    }
}
