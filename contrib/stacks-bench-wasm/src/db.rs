use std::path::Path;

use rusqlite::functions::{Aggregate, Context, FunctionFlags};
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

        conn.create_aggregate_function("VAR", 1, FunctionFlags::empty(), VarAggregator)?;

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

    pub fn iter_metrics(&mut self) -> Result<Vec<Metrics>> {
        let tx = self.conn.transaction()?;

        let mut stmt = tx.prepare(QUERY_METRICS)?;
        let metrics_iter = stmt.query_map([], |row| {
            Ok(Metrics {
                wasm: row.get(0)?,
                calls: row.get(1)?,
                avg: row.get(2)?,
                var: row.get(3)?,
            })
        })?;

        metrics_iter.collect()
    }
}

pub struct Metrics {
    pub wasm: bool,
    pub calls: u64,
    pub avg: f64,
    pub var: f64,
}

struct VarContext {
    avg: f64,
    var: f64,
    rows: u64,
}

struct VarAggregator;

impl Aggregate<VarContext, Option<f64>> for VarAggregator {
    fn init(&self, _ctx: &mut Context<'_>) -> Result<VarContext> {
        Ok(VarContext {
            avg: 0.0,
            var: 0.0,
            rows: 1,
        })
    }

    fn step(&self, ctx: &mut Context<'_>, acc: &mut VarContext) -> Result<()> {
        let val = ctx.get::<f64>(1)?;

        // welford's method
        let tmp_avg = acc.avg;
        acc.avg += (val - tmp_avg) / acc.rows as f64;
        acc.var += (val - tmp_avg) * (val - acc.avg);
        acc.rows += 1;

        Ok(())
    }

    fn finalize(&self, _ctx: &mut Context<'_>, acc: Option<VarContext>) -> Result<Option<f64>> {
        Ok(acc.map(|metrics_ctx| metrics_ctx.var / (metrics_ctx.rows - 1) as f64))
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

const QUERY_METRICS: &str = "SELECT wasm, calls, AVG(runtime), VAR(runtime) \
    FROM bench \
    WHERE error IS NULL \
    GROUP BY wasm, calls
";
