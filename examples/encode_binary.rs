//! Library usage example, mirroring the original Go `encode_x64_binary` sample.
//!
//! Run with: `cargo run --example encode_binary -- path/to/payload.bin`

use sgn::Encoder;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: encode_binary <file>");
        std::process::exit(1);
    });

    // Read the raw payload.
    let file = match std::fs::read(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    // Create a new 64-bit SGN encoder and encode the binary.
    let mut encoder = Encoder::new(64).expect("valid architecture");
    let encoded = match encoder.encode(&file) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    // Print a hex dump of the encoded binary.
    for (i, chunk) in encoded.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        println!("{:08x}  {}", i * 16, hex);
    }
}
