/// Generate the standard library as a Wasm binary from the WAT source.
#[allow(clippy::expect_used)]
fn main() {
    println!("cargo:rerun-if-changed=src/vm/wasm/standard/standard.wat");

    match wat::parse_file("src/vm/wasm/standard/standard.wat") {
        Ok(binary) => {
            std::fs::write("src/vm/wasm/standard/standard.wasm", binary)
                .expect("Failed to write standard library");
        }
        Err(error) => {
            panic!("Failed to parse standard library: {error}");
        }
    };
}
