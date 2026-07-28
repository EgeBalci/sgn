//! End-to-end validation: encode a payload and actually execute the resulting
//! x64 shellcode in-process, confirming it decodes itself and runs the original
//! payload. This is the Linux analogue of the original project's Windows
//! `VirtualAlloc` stress test.
//!
//! The test payload is `mov eax, 0x1337c0de; ret`, so a correct decode returns
//! the sentinel in RAX. These tests only run on x86-64 Linux.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use iced_x86::code_asm::*;
use sgn::Encoder;

const MAGIC: u64 = 0x1337_c0de;
/// mov eax, 0x1337c0de ; ret
const PAYLOAD: &[u8] = &[0xb8, 0xde, 0xc0, 0x37, 0x13, 0xc3];

/// Wraps `shell` in a trampoline that preserves the System-V callee-saved
/// registers (RBX, RBP, R12–R15) across execution. SGN shellcode freely
/// clobbers general-purpose registers — which is fine for real payloads that
/// never return to an ABI-respecting caller — so the test harness must isolate
/// the call itself.
fn trampoline(shell: &[u8]) -> Vec<u8> {
    let mut a = CodeAssembler::new(64).unwrap();
    a.push(rbx).unwrap();
    a.push(rbp).unwrap();
    a.push(r12).unwrap();
    a.push(r13).unwrap();
    a.push(r14).unwrap();
    a.push(r15).unwrap();
    let mut target = a.create_label();
    a.call(target).unwrap();
    a.pop(r15).unwrap();
    a.pop(r14).unwrap();
    a.pop(r13).unwrap();
    a.pop(r12).unwrap();
    a.pop(rbp).unwrap();
    a.pop(rbx).unwrap();
    a.ret().unwrap();
    a.set_label(&mut target).unwrap();
    a.db(shell).unwrap();
    a.assemble(0).unwrap()
}

/// Maps `shell` (wrapped in a register-preserving trampoline) as executable
/// memory and calls it. Returns `None` if the environment refuses executable
/// mappings.
unsafe fn run(shell: &[u8]) -> Option<u64> {
    let code = trampoline(shell);
    let code = code.as_slice();
    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let len = code.len().div_ceil(page) * page;

    // Try a directly-RWX mapping first; fall back to RW + mprotect(RWX).
    let mut mem = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if mem == libc::MAP_FAILED {
        mem = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if mem == libc::MAP_FAILED {
            return None;
        }
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
        if libc::mprotect(mem, len, libc::PROT_READ | libc::PROT_EXEC | libc::PROT_WRITE) != 0 {
            libc::munmap(mem, len);
            return None;
        }
    } else {
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
    }

    let func: extern "C" fn() -> u64 = std::mem::transmute(mem);
    let result = func();
    libc::munmap(mem, len);
    Some(result)
}

fn encode(configure: impl FnOnce(&mut Encoder)) -> Vec<u8> {
    let mut enc = Encoder::new(64).unwrap();
    configure(&mut enc);
    enc.encode(PAYLOAD).unwrap()
}

#[test]
fn default_schema_encoding_executes() {
    let code = encode(|_| {});
    match unsafe { run(&code) } {
        Some(v) => assert_eq!(v & 0xffff_ffff, MAGIC, "decoded payload returned wrong value"),
        None => eprintln!("skipped: executable memory unavailable"),
    }
}

#[test]
fn plain_decoder_executes() {
    let code = encode(|e| e.plain_decoder = true);
    if let Some(v) = unsafe { run(&code) } {
        assert_eq!(v & 0xffff_ffff, MAGIC);
    }
}

#[test]
fn multiple_encoding_layers_execute() {
    let code = encode(|e| e.encoding_count = 3);
    if let Some(v) = unsafe { run(&code) } {
        assert_eq!(v & 0xffff_ffff, MAGIC);
    }
}

#[test]
fn zero_obfuscation_executes() {
    let code = encode(|e| e.obfuscation_limit = 0);
    if let Some(v) = unsafe { run(&code) } {
        assert_eq!(v & 0xffff_ffff, MAGIC);
    }
}

#[test]
fn safe_registers_plain_executes() {
    // In safe mode the payload is wrapped in PUSHAD/POPAD-style save/restore.
    // A `nop` payload does nothing observable, so we append our own
    // `mov eax, MAGIC; ret` continuation: execution falls through the restore
    // suffix into it. If the register-restore prologue/epilogue were unbalanced,
    // the trailing `ret` would fault — so a correct return validates them.
    let nop_payload: &[u8] = &[0x90, 0x90, 0x90];
    let mut enc = Encoder::new(64).unwrap();
    enc.save_registers = true;
    enc.plain_decoder = true;
    let mut code = enc.encode(nop_payload).unwrap();
    code.extend_from_slice(PAYLOAD); // continuation: mov eax, MAGIC; ret

    if let Some(v) = unsafe { run(&code) } {
        assert_eq!(v & 0xffff_ffff, MAGIC);
    }
}

#[test]
fn stress_many_random_encodings_execute() {
    // Each iteration produces a fresh polymorphic variant; all must decode and
    // run correctly. Catches rare register/offset combinations.
    let mut executed = 0;
    for i in 0..300 {
        let code = encode(|_| {});
        match unsafe { run(&code) } {
            Some(v) => {
                assert_eq!(v & 0xffff_ffff, MAGIC, "iteration {i} decoded incorrectly");
                executed += 1;
            }
            None => {
                eprintln!("skipped: executable memory unavailable");
                return;
            }
        }
    }
    assert_eq!(executed, 300);
}
