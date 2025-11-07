use std::path::Path;

use rusqlite::{Connection, Error};

type Result<T> = std::result::Result<T, Error>;

pub struct Bench {
    pub block_hash: String,
    pub wasm: bool,
    pub runtime: u64,
    pub calls: u64,
    pub error: Option<String>,
}

pub fn init_bench(path: impl AsRef<Path>) -> Result<()> {
    let mut conn = Connection::open(path)?;

    let tx = conn.transaction()?;
    tx.execute(CREATE_BENCH_TABLE, ())?;
    tx.execute(CREATE_BENCH_WASM_INDEX, ())?;
    tx.execute(CREATE_BENCH_CALLS_INDEX, ())?;
    tx.commit()?;

    Ok(())
}

pub fn insert_bench(path: impl AsRef<Path>, bench: &Bench) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        INSERT_BENCH,
        (
            &bench.block_hash,
            &bench.wasm,
            &bench.runtime,
            &bench.calls,
            &bench.error,
        ),
    )?;
    Ok(())
}

const CREATE_BENCH_TABLE: &str = "CREATE TABLE IF NOT EXISTS bench ( \
    block_hash  TEXT NOT NULL, \
    wasm        INTEGER NOT NULL, \
    runtime     INTEGER NOT NULL, \
    calls       INTEGER NOT NULL, \
    error       TEXT, \
    PRIMARY KEY (block_hash, wasm) ON CONFLICT REPLACE
)";

const CREATE_BENCH_WASM_INDEX: &str = "CREATE INDEX IF NOT EXISTS \
    bench_idx_wasm ON bench(wasm)";
const CREATE_BENCH_CALLS_INDEX: &str = "CREATE INDEX IF NOT EXISTS \
    bench_idx_wasm ON bench(calls)";

const INSERT_BENCH: &str = "INSERT INTO bench \
    (block_hash, wasm, runtime, calls, error) \
    VALUES \
    (?1, ?2, ?3, ?4, ?5)
";
