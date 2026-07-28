//! Random garbage-instruction generation.
//!
//! The original Go implementation built garbage as keystone assembly *text*
//! from templates like `"CMOVA {R},{R}"` and `"ADD {R},{K};{G};SUB {R},{K}"`.
//! Here we emit the equivalent instructions directly through `iced-x86`'s
//! assembler. Every instruction is *value-preserving* for the registers it
//! touches (shift/rotate by zero, `xor r,0`, `mov r,r`, `cmovcc r,r`, or a
//! self-cancelling pair wrapped around nested garbage), so garbage may safely
//! use any register — including ones the decoder relies on — without disturbing
//! the payload. Flags are considered scratch and may be clobbered.

use crate::registers::{random_gp, reg32, reg64};
use iced_x86::code_asm::{CodeAssembler, IcedError};
use rand::Rng;

/// Maximum nesting depth for recursive garbage templates. The original relied
/// purely on coin flips to terminate; a hard cap keeps generation bounded.
const MAX_DEPTH: u32 = 6;

/// Emits a reg,reg instruction for the architecture's full-size register.
macro_rules! rr {
    ($a:expr, $arch:expr, $ri:expr, $m:ident) => {
        if $arch == 64 {
            $a.$m(reg64($ri), reg64($ri))?;
        } else {
            $a.$m(reg32($ri), reg32($ri))?;
        }
    };
}

/// Emits a reg,imm instruction for the architecture's full-size register.
macro_rules! ri {
    ($a:expr, $arch:expr, $idx:expr, $m:ident, $imm:expr) => {
        if $arch == 64 {
            $a.$m(reg64($idx), $imm)?;
        } else {
            $a.$m(reg32($idx), $imm)?;
        }
    };
}

/// Emits a single-register instruction for the architecture's full-size register.
macro_rules! r1 {
    ($a:expr, $arch:expr, $idx:expr, $m:ident) => {
        if $arch == 64 {
            $a.$m(reg64($idx))?;
        } else {
            $a.$m(reg32($idx))?;
        }
    };
}

/// Emits a random conditional jump to `label`.
fn emit_jcc<R: Rng>(
    a: &mut CodeAssembler,
    rng: &mut R,
    label: iced_x86::code_asm::CodeLabel,
) -> Result<(), IcedError> {
    match rng.gen_range(0..30) {
        0 => a.ja(label),
        1 => a.jae(label),
        2 => a.jb(label),
        3 => a.jbe(label),
        4 => a.jc(label),
        5 => a.je(label),
        6 => a.jg(label),
        7 => a.jge(label),
        8 => a.jl(label),
        9 => a.jle(label),
        10 => a.jna(label),
        11 => a.jnae(label),
        12 => a.jnb(label),
        13 => a.jnbe(label),
        14 => a.jnc(label),
        15 => a.jne(label),
        16 => a.jng(label),
        17 => a.jnge(label),
        18 => a.jnl(label),
        19 => a.jnle(label),
        20 => a.jno(label),
        21 => a.jnp(label),
        22 => a.jns(label),
        23 => a.jnz(label),
        24 => a.jo(label),
        25 => a.jp(label),
        26 => a.jpe(label),
        27 => a.jpo(label),
        28 => a.js(label),
        _ => a.jz(label),
    }
}

/// Emits a random value-preserving `cmovcc r,r`.
fn emit_cmov<R: Rng>(
    a: &mut CodeAssembler,
    rng: &mut R,
    arch: u32,
    ri: usize,
) -> Result<(), IcedError> {
    match rng.gen_range(0..30) {
        0 => rr!(a, arch, ri, cmova),
        1 => rr!(a, arch, ri, cmovae),
        2 => rr!(a, arch, ri, cmovb),
        3 => rr!(a, arch, ri, cmovbe),
        4 => rr!(a, arch, ri, cmovc),
        5 => rr!(a, arch, ri, cmove),
        6 => rr!(a, arch, ri, cmovg),
        7 => rr!(a, arch, ri, cmovge),
        8 => rr!(a, arch, ri, cmovl),
        9 => rr!(a, arch, ri, cmovle),
        10 => rr!(a, arch, ri, cmovna),
        11 => rr!(a, arch, ri, cmovnae),
        12 => rr!(a, arch, ri, cmovnb),
        13 => rr!(a, arch, ri, cmovnbe),
        14 => rr!(a, arch, ri, cmovnc),
        15 => rr!(a, arch, ri, cmovne),
        16 => rr!(a, arch, ri, cmovng),
        17 => rr!(a, arch, ri, cmovnge),
        18 => rr!(a, arch, ri, cmovnl),
        19 => rr!(a, arch, ri, cmovnle),
        20 => rr!(a, arch, ri, cmovno),
        21 => rr!(a, arch, ri, cmovnp),
        22 => rr!(a, arch, ri, cmovns),
        23 => rr!(a, arch, ri, cmovnz),
        24 => rr!(a, arch, ri, cmovo),
        25 => rr!(a, arch, ri, cmovp),
        26 => rr!(a, arch, ri, cmovpe),
        27 => rr!(a, arch, ri, cmovpo),
        28 => rr!(a, arch, ri, cmovs),
        _ => rr!(a, arch, ri, cmovz),
    }
    Ok(())
}

/// Recursively emits a random garbage instruction (or nothing) into `a`.
/// Mirrors the original `GenerateGarbageAssembly`: at each level there is a
/// 50% chance of emitting nothing, otherwise one (possibly nested) template.
fn emit_garbage<R: Rng>(
    a: &mut CodeAssembler,
    rng: &mut R,
    arch: u32,
    depth: u32,
) -> Result<(), IcedError> {
    if depth == 0 || rng.gen::<bool>() {
        return Ok(());
    }

    let idx = random_gp(rng, arch);
    // Immediates are passed as i32: iced only implements the r64 arithmetic
    // forms for i32 (sign-extended imm32), and accepts i32 for r32 and shifts.
    let k = rng.gen::<u8>() as i32;

    match rng.gen_range(0..8) {
        // Zero-operand, no-effect instructions.
        0 => match rng.gen_range(0..8) {
            0 => a.nop()?,
            1 => a.cld()?,
            2 => a.clc()?,
            3 => a.cmc()?,
            4 => a.wait()?,
            5 => a.fnop()?,
            6 => a.fxam()?,
            _ => a.ftst()?,
        },
        // Shift / rotate by zero (value- and flag-preserving).
        1 => match rng.gen_range(0..7) {
            0 => ri!(a, arch, idx, rol, 0i32),
            1 => ri!(a, arch, idx, ror, 0i32),
            2 => ri!(a, arch, idx, shl, 0i32),
            3 => ri!(a, arch, idx, shr, 0i32),
            4 => ri!(a, arch, idx, rcl, 0i32),
            5 => ri!(a, arch, idx, rcr, 0i32),
            _ => ri!(a, arch, idx, sar, 0i32),
        },
        // Arithmetic with identity operand.
        2 => match rng.gen_range(0..3) {
            0 => ri!(a, arch, idx, xor, 0i32),
            1 => ri!(a, arch, idx, sub, 0i32),
            _ => ri!(a, arch, idx, add, 0i32),
        },
        // reg,reg no-ops.
        3 => match rng.gen_range(0..7) {
            0 => rr!(a, arch, idx, and),
            1 => rr!(a, arch, idx, or),
            2 => rr!(a, arch, idx, bt),
            3 => rr!(a, arch, idx, cmp),
            4 => rr!(a, arch, idx, mov),
            5 => rr!(a, arch, idx, xchg),
            _ => rr!(a, arch, idx, test),
        },
        // Conditional move, self-target.
        4 => emit_cmov(a, rng, arch, idx)?,
        // Jump (conditional or unconditional) over nested garbage.
        5 => {
            let mut label = a.create_label();
            if rng.gen::<bool>() {
                a.jmp(label)?;
            } else {
                emit_jcc(a, rng, label)?;
            }
            emit_garbage(a, rng, arch, depth - 1)?;
            a.set_label(&mut label)?;
            a.zero_bytes()?;
        }
        // Self-cancelling unary pair wrapping nested garbage.
        6 => {
            let (first, second): (u8, u8) = match rng.gen_range(0..4) {
                0 => (0, 0), // not / not
                1 => (1, 1), // neg / neg
                2 => (2, 3), // inc / dec
                _ => (3, 2), // dec / inc
            };
            emit_unary(a, arch, idx, first)?;
            emit_garbage(a, rng, arch, depth - 1)?;
            emit_unary(a, arch, idx, second)?;
        }
        // Self-cancelling binary pair wrapping nested garbage.
        _ => {
            match rng.gen_range(0..4) {
                0 => {
                    ri!(a, arch, idx, add, k);
                    emit_garbage(a, rng, arch, depth - 1)?;
                    ri!(a, arch, idx, sub, k);
                }
                1 => {
                    ri!(a, arch, idx, sub, k);
                    emit_garbage(a, rng, arch, depth - 1)?;
                    ri!(a, arch, idx, add, k);
                }
                2 => {
                    ri!(a, arch, idx, rol, k);
                    emit_garbage(a, rng, arch, depth - 1)?;
                    ri!(a, arch, idx, ror, k);
                }
                _ => {
                    ri!(a, arch, idx, ror, k);
                    emit_garbage(a, rng, arch, depth - 1)?;
                    ri!(a, arch, idx, rol, k);
                }
            }
        }
    }

    Ok(())
}

/// Emits one of the four unary self-cancelling operations by code.
fn emit_unary(a: &mut CodeAssembler, arch: u32, idx: usize, op: u8) -> Result<(), IcedError> {
    match op {
        0 => r1!(a, arch, idx, not),
        1 => r1!(a, arch, idx, neg),
        2 => r1!(a, arch, idx, inc),
        _ => r1!(a, arch, idx, dec),
    }
    Ok(())
}

/// Emits a short jump over `count` random bytes (`jmp over; <random>; over:`).
fn emit_garbage_jump<R: Rng>(
    a: &mut CodeAssembler,
    rng: &mut R,
    count: usize,
) -> Result<(), IcedError> {
    let mut over = a.create_label();
    a.jmp(over)?;
    let junk: Vec<u8> = (0..count).map(|_| rng.gen()).collect();
    a.db(&junk)?;
    a.set_label(&mut over)?;
    a.zero_bytes()?;
    Ok(())
}

/// Generates a block of random garbage machine code no larger than
/// `obfuscation_limit` bytes. Returns an empty vector when the limit is zero or
/// negative (obfuscation disabled). Mirrors `GenerateGarbageInstructions`.
pub fn generate_garbage<R: Rng>(
    rng: &mut R,
    arch: u32,
    obfuscation_limit: i32,
) -> Result<Vec<u8>, IcedError> {
    if obfuscation_limit <= 0 {
        return Ok(Vec::new());
    }
    let limit = obfuscation_limit as usize;

    loop {
        let mut a = CodeAssembler::new(arch)?;

        // Optionally wrap the garbage with a jump over random bytes, before or
        // after, matching the original's coin-flip placement.
        let jump = coin(rng);
        let jump_before = jump && coin(rng);
        if jump && jump_before {
            emit_garbage_jump(&mut a, rng, limit / 10)?;
        }
        emit_garbage(&mut a, rng, arch, MAX_DEPTH)?;
        if jump && !jump_before {
            emit_garbage_jump(&mut a, rng, limit / 10)?;
        }

        let bytes = a.assemble(0)?;
        if bytes.len() <= limit {
            return Ok(bytes);
        }
        // Too large; try again with fresh randomness.
    }
}

fn coin<R: Rng>(rng: &mut R) -> bool {
    rng.gen()
}

/// Computes the average size of generated garbage instructions over 100 samples.
/// Used only for the verbose diagnostic line.
pub fn average_garbage_size<R: Rng>(rng: &mut R, arch: u32) -> Result<f64, IcedError> {
    let mut total = 0usize;
    for _ in 0..100 {
        let mut a = CodeAssembler::new(arch)?;
        emit_garbage(&mut a, rng, arch, MAX_DEPTH)?;
        total += a.assemble(0)?.len();
    }
    Ok(total as f64 / 100.0)
}
