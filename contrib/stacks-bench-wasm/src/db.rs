use std::path::Path;

use rusqlite::{Connection, Error};

type Result<T> = std::result::Result<T, Error>;

pub struct BenchDatabase {
    conn: Connection,
}

impl BenchDatabase {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut conn = Connection::open(path)?;

        let tx = conn.transaction()?;
        tx.execute(CREATE_BENCH_TABLE, ())?;
        tx.execute(CREATE_BENCH_INDEX, ())?;
        tx.commit()?;

        Ok(Self { conn })
    }

    pub fn insert_bench(&mut self, bench: &Bench) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            INSERT_BENCH,
            (
                &bench.block_hash,
                &bench.wasm,
                &bench.runtime,
                &bench.calls,
                &bench.error,
            ),
        )?;
        tx.commit()
    }
}

pub struct Bench {
    pub block_hash: String,
    pub wasm: bool,
    pub runtime: u64,
    pub calls: u64,
    pub error: Option<String>,
}

const CREATE_BENCH_TABLE: &str = "CREATE TABLE IF NOT EXISTS bench ( \
    block_hash  TEXT NOT NULL, \
    wasm        INTEGER NOT NULL, \
    runtime     INTEGER NOT NULL, \
    calls       INTEGER NOT NULL, \
    error       TEXT, \
    PRIMARY KEY (block_hash, wasm) ON CONFLICT REPLACE
)";

const CREATE_BENCH_INDEX: &str = "CREATE INDEX IF NOT EXISTS \
    bench_idx ON bench(wasm, calls)";

const INSERT_BENCH: &str = "INSERT INTO bench \
    (block_hash, wasm, runtime, calls, error) \
    VALUES \
    (?1, ?2, ?3, ?4, ?5)
";
