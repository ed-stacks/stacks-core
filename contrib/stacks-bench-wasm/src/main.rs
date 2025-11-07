// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::path::PathBuf;

use clap::Parser;

use stackslib::config::{Config, ConfigFile};

/// Execute slices of the blockchain by block height, inserting some captured
/// values in the benchmark database
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the blockchain database
    chain_db: PathBuf,
    /// Path to the benchmarks database
    bench_db: PathBuf,
    /// Height of the first block to replay (inclusive)
    start_height: u64,
    /// Height of the last block to replay (inclusive)
    end_height: u64,
    /// Path to a custom network configuration file
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let config_file = match args.config {
        None => ConfigFile::mainnet(),
        Some(config_path) => ConfigFile::from_path(&*config_path.to_string_lossy())
            .expect("Failed loading network configfile"),
    };
    let config = Config::from_config_file(config_file, false)
        .expect("Failed loading network config from file");

    stacks_bench_wasm::command_bench(
        args.chain_db.to_string_lossy().to_string(),
        args.bench_db.to_string_lossy().to_string(),
        args.start_height,
        args.end_height,
        config,
    )?;

    Ok(())
}
