# stacks-bench-wasm

Run and persist comparative benchmarks of the interpreter vs. the WASM runtime

## Description
This package produces an executable named `stacks-bench-wasm` that, given the
paths of the chainstate and benchmark databases (SQLite), will perform block
(re)runs of given slices of the chainstate. The details of these runs are
saved to the benchmark database, and the same executable can be used to display
different statistics collected in the database

## Build
The executable can be built separate ways: one for using the interpreter, and
another for using the WASM runtime

```sh
# Build with the interpreter
cargo build --release -p stacks-bench-wasm
# Build with the WASM runtime
cargo build --release -p stacks-bench-wasm --features=clarity-wasm
```

## Usage
```sh
cargo run --release -p stacks-bench-wasm -- --help
```
