//! SGN command-line interface.

use clap::Parser;
use sgn::util::{
    contains_bytes, is_ascii_printable, print_blue, print_fatal, print_status, print_success,
    print_verbose, set_verbose,
};
use sgn::Encoder;
use std::process::ExitCode;

const BANNER: &str = r#"
       __   _ __        __                               _
  ___ / /  (_) /_____ _/ /____ _  ___ ____ _  ___  ___ _(_)
 (_-</ _ \/ /  '_/ _ `/ __/ _ `/ / _ `/ _ `/ / _ \/ _ `/ /
/___/_//_/_/_/\_\\_,_/\__/\_,_/  \_, /\_,_/ /_//_/\_,_/_/
========[Author:-Ege-Balcı-]====/___/=======v{VER}=========
    ┻━┻ ︵ヽ(`Д´)ﾉ︵ ┻━┻           (ノ ゜Д゜)ノ ︵ 仕方がない
"#;

/// SGN — polymorphic binary encoder.
#[derive(Parser, Debug)]
#[command(name = "sgn", version, about = "SGN polymorphic binary encoder", long_about = None)]
struct Cli {
    /// Input binary path
    #[arg(short = 'i', long = "input")]
    input: Option<String>,

    /// Encoded output binary name
    #[arg(short = 'o', long = "out")]
    out: Option<String>,

    /// Binary architecture (32/64)
    #[arg(short = 'a', long = "arch", default_value_t = 64)]
    arch: u32,

    /// Number of times to encode the binary (increases overall size)
    #[arg(short = 'c', long = "enc", default_value_t = 1)]
    enc: u32,

    /// Maximum number of bytes for decoder obfuscation
    #[arg(short = 'M', long = "max", default_value_t = 50)]
    max: i32,

    /// Do not encode the decoder stub
    #[arg(long = "plain")]
    plain: bool,

    /// Generate a fully ASCII-printable payload (may take a long time to brute-force)
    #[arg(long = "ascii")]
    ascii: bool,

    /// Preserve all register values (a.k.a. no clobber)
    #[arg(short = 'S', long = "safe")]
    safe: bool,

    /// Don't use the specified bad characters, given in hex (e.g. \x00\x01\x02)
    #[arg(long = "badchars", default_value = "")]
    badchars: String,

    /// Verbose mode
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

/// Parses a bad-character hex string such as `\x00\x0a` (or `000a`) into bytes.
fn parse_bad_chars(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.replace("\\x", "").chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("bad characters must be an even number of hex digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    println!("{}", BANNER.replace("{VER}", env!("CARGO_PKG_VERSION")));

    if cli.verbose {
        set_verbose(true);
    }

    let input = match &cli.input {
        Some(p) => p.clone(),
        None => print_fatal("input file parameter is mandatory (-i/--input)"),
    };

    let file = match std::fs::read(&input) {
        Ok(f) => f,
        Err(e) => print_fatal(&format!("cannot read input '{input}': {e}")),
    };

    let mut encoder = match Encoder::new(cli.arch) {
        Ok(e) => e,
        Err(e) => print_fatal(&format!("{e}")),
    };
    encoder.obfuscation_limit = cli.max;
    encoder.plain_decoder = cli.plain;
    encoder.encoding_count = cli.enc;
    encoder.save_registers = cli.safe;

    let bad_bytes = match parse_bad_chars(&cli.badchars) {
        Ok(b) => b,
        Err(e) => print_fatal(&format!("invalid bad characters: {e}")),
    };

    print_verbose(&format!("Architecture: x{}", encoder.architecture));
    print_verbose(&format!("Encode Count: {}", encoder.encoding_count));
    print_verbose(&format!("Max. Obfuscation Size: {}", encoder.obfuscation_limit));
    print_verbose(&format!("Bad Characters: {}", hex(&bad_bytes)));
    print_verbose(&format!("ASCII Mode: {}", cli.ascii));
    print_verbose(&format!("Plain Decoder: {}", encoder.plain_decoder));
    print_verbose(&format!("Safe Registers: {}", encoder.save_registers));

    let mut rng = rand::thread_rng();
    if let Ok(avg) = sgn::obfuscate::average_garbage_size(&mut rng, encoder.architecture) {
        print_verbose(&format!("Avg. Garbage Size: {avg:.2}"));
    }

    // Encode (brute-forcing the seed when constraints are requested).
    let payload = if !bad_bytes.is_empty() || cli.ascii {
        if !cli.verbose {
            print_status("Bruteforcing bad characters...");
        }
        encode_constrained(&mut encoder, &file, &bad_bytes, cli.ascii)
    } else {
        print_verbose("Encoding payload...");
        match encoder.encode(&file) {
            Ok(p) => p,
            Err(e) => print_fatal(&format!("{e}")),
        }
    };

    let output = cli.out.clone().unwrap_or_else(|| format!("{input}.sgn"));

    print_status(&format!("Input: {input}"));
    print_status(&format!("Input Size: {}", file.len()));
    print_status(&format!("Outfile: {output}"));

    if let Err(e) = std::fs::write(&output, &payload) {
        print_fatal(&format!("cannot write output '{output}': {e}"));
    }

    if cli.verbose {
        print_blue(&format!("\n{}", hex_dump(&payload)));
    }

    print_success(&format!("Final size: {}", payload.len()));
    print_success("All done ＼(＾O＾)／");
    ExitCode::SUCCESS
}

/// Repeatedly encodes with an incrementing seed until the output satisfies the
/// ASCII and/or bad-character constraints.
fn encode_constrained(
    encoder: &mut Encoder,
    file: &[u8],
    bad_bytes: &[u8],
    ascii: bool,
) -> Vec<u8> {
    let obf = encoder.obfuscation_limit;
    let count = encoder.encoding_count;
    let safe = encoder.save_registers;
    loop {
        // Reset the per-run counters mutated by encode_with.
        encoder.obfuscation_limit = obf;
        encoder.encoding_count = count;
        encoder.save_registers = safe;

        let p = match encoder.encode(file) {
            Ok(p) => p,
            Err(e) => print_fatal(&format!("{e}")),
        };

        let ascii_ok = !ascii || is_ascii_printable(&p);
        let bad_ok = bad_bytes.is_empty() || !contains_bytes(&p, bad_bytes);
        if ascii_ok && bad_ok {
            print_status("Success ᕕ( ᐛ )ᕗ");
            return p;
        }
        encoder.seed = encoder.seed.wrapping_add(1);
    }
}

/// Lowercase hex encoding of a byte slice.
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// A compact `hexdump -C`-style rendering used for the verbose dump.
fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut hexpart = String::new();
        let mut ascii = String::new();
        for (j, &b) in chunk.iter().enumerate() {
            hexpart.push_str(&format!("{b:02x} "));
            if j == 7 {
                hexpart.push(' ');
            }
            ascii.push(if (0x20..=0x7e).contains(&b) { b as char } else { '.' });
        }
        out.push_str(&format!("{:08x}  {:<49}|{}|\n", i * 16, hexpart, ascii));
    }
    out
}
