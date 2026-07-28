//! 32-bit end-to-end execution test.
//!
//! A 64-bit process can't directly call 32-bit shellcode, so this test shells
//! out to a tiny C harness compiled with `cc -m32`. If a 32-bit toolchain isn't
//! available the test skips cleanly. Each SGN-encoded payload is wrapped in a
//! trampoline that preserves the i386 SysV callee-saved registers.

#![cfg(target_os = "linux")]

use iced_x86::code_asm::*;
use sgn::Encoder;
use std::path::{Path, PathBuf};
use std::process::Command;

const HARNESS_SRC: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) return 4;
    fclose(f);
    long pg = sysconf(_SC_PAGESIZE);
    long len = ((n + pg - 1) / pg) * pg;
    void *mem = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 5;
    memcpy(mem, buf, n);
    unsigned int result;
    __asm__ volatile("call *%1" : "=a"(result) : "r"(mem) : "ecx","edx","memory");
    return (result == 0x1337c0de) ? 0 : 1;
}
"#;

/// mov eax, 0x1337c0de ; ret
const PAYLOAD: &[u8] = &[0xb8, 0xde, 0xc0, 0x37, 0x13, 0xc3];

/// Wraps 32-bit shellcode, preserving i386 callee-saved registers.
fn trampoline32(shell: &[u8]) -> Vec<u8> {
    let mut a = CodeAssembler::new(32).unwrap();
    a.push(ebx).unwrap();
    a.push(esi).unwrap();
    a.push(edi).unwrap();
    a.push(ebp).unwrap();
    let mut target = a.create_label();
    a.call(target).unwrap();
    a.pop(ebp).unwrap();
    a.pop(edi).unwrap();
    a.pop(esi).unwrap();
    a.pop(ebx).unwrap();
    a.ret().unwrap();
    a.set_label(&mut target).unwrap();
    a.db(shell).unwrap();
    a.assemble(0).unwrap()
}

/// Compiles the harness with `cc -m32`; returns its path or `None` if the
/// toolchain is unavailable.
fn build_harness(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("harness32.c");
    let bin = dir.join("harness32");
    std::fs::write(&src, HARNESS_SRC).ok()?;
    let status = Command::new("cc")
        .args(["-m32", "-O2"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .ok()?;
    if status.success() {
        Some(bin)
    } else {
        None
    }
}

#[test]
fn x86_shellcode_executes() {
    let dir = std::env::temp_dir().join(format!("sgn32_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let harness = match build_harness(&dir) {
        Some(h) => h,
        None => {
            eprintln!("skipped: no 32-bit C toolchain (cc -m32) available");
            return;
        }
    };

    let bin = dir.join("sc.bin");
    let modes: [&dyn Fn(&mut Encoder); 4] = [
        &|_e: &mut Encoder| {},
        &|e: &mut Encoder| e.plain_decoder = true,
        &|e: &mut Encoder| e.encoding_count = 3,
        &|e: &mut Encoder| e.obfuscation_limit = 0,
    ];

    let mut runs = 0;
    for cfg in modes {
        for _ in 0..60 {
            let mut enc = Encoder::new(32).unwrap();
            enc.obfuscation_limit = 50;
            cfg(&mut enc);
            let code = trampoline32(&enc.encode(PAYLOAD).unwrap());
            std::fs::write(&bin, &code).unwrap();
            let status = Command::new(&harness).arg(&bin).status().unwrap();
            assert!(
                status.success(),
                "32-bit shellcode did not decode to the expected value"
            );
            runs += 1;
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(runs, 240);
}
