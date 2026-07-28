//! CLI integration tests: drive the built `sgn` binary end to end.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sgn")
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("sgn_cli_{}_{}", std::process::id(), name))
}

#[test]
fn encodes_a_file() {
    let input = tmp("in.bin");
    let output = tmp("out.bin");
    std::fs::write(&input, b"\x90\x90\x90\xc3").unwrap();

    let status = Command::new(bin())
        .args(["-i", input.to_str().unwrap(), "-o", output.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let encoded = std::fs::read(&output).unwrap();
    assert!(!encoded.is_empty());

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn respects_bad_characters() {
    let input = tmp("bad_in.bin");
    let output = tmp("bad_out.bin");
    std::fs::write(&input, b"\x90\x90\x90\xc3").unwrap();

    // NOTE: 0x00 is intentionally NOT excluded here. Like the original SGN, the
    // decoder stub's `mov ecx, <size>` immediate carries high zero bytes for any
    // realistic payload size, so a null-free encoding is unattainable for small
    // inputs. 0x0a/0x0d are not structurally forced and are quickly brute-forced.
    let bad = [0x0au8, 0x0d];
    let status = Command::new(bin())
        .args([
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--badchars",
            r"\x0a\x0d",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let encoded = std::fs::read(&output).unwrap();
    assert!(!encoded.is_empty());
    for &b in &bad {
        assert!(!encoded.contains(&b), "output contains bad byte {b:#04x}");
    }

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn missing_input_fails() {
    let status = Command::new(bin()).status().unwrap();
    assert!(!status.success());
}
