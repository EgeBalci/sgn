//! Small helpers: bad-character detection, ASCII-printable checks and the
//! colored status printers used by the CLI.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbose switch, mirroring the Go `utils.Verbose` package global.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enables or disables verbose output.
pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

/// Reports whether verbose output is enabled.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Reports whether `data` contains at least one byte that also appears in
/// `bad`. Used to reject encoder output containing forbidden bytes.
pub fn contains_bytes(data: &[u8], bad: &[u8]) -> bool {
    // Build a 256-entry membership table so detection is O(len(data)) instead
    // of O(len(data) * len(bad)) as in the original nested-loop version.
    let mut table = [false; 256];
    for &b in bad {
        table[b as usize] = true;
    }
    data.iter().any(|&b| table[b as usize])
}

/// Reports whether every byte in `data` is an ASCII printable character
/// (0x20..=0x7e). Backs the `--ascii` brute-force mode.
pub fn is_ascii_printable(data: &[u8]) -> bool {
    data.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

// ANSI color codes; emitted directly to avoid an external color dependency.
const BOLD_YELLOW: &str = "\x1b[1;33m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const BOLD_RED: &str = "\x1b[1;31m";
const BLUE: &str = "\x1b[34m";
const RESET: &str = "\x1b[0m";

/// Prints an informational status line prefixed with a bold-yellow marker.
pub fn print_status(msg: &str) {
    println!("{BOLD_YELLOW}[*] {RESET}{msg}");
}

/// Prints a success line prefixed with a bold-green marker.
pub fn print_success(msg: &str) {
    println!("{BOLD_GREEN}[+] {RESET}{msg}");
}

/// Prints an error line prefixed with a bold-red marker and exits non-zero.
pub fn print_fatal(msg: &str) -> ! {
    eprintln!("{BOLD_RED}[-] {RESET}{msg}");
    std::process::exit(1);
}

/// Prints a diagnostic line, but only when verbose output is enabled.
pub fn print_verbose(msg: &str) {
    if verbose() {
        println!("{BOLD_YELLOW}[*] {RESET}{msg}");
    }
}

/// Prints text in blue (used for the hex dump under `-v`).
pub fn print_blue(msg: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{BLUE}{msg}{RESET}");
}
