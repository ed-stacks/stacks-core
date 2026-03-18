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

#[macro_use]
extern crate stacks_common;

use std::backtrace::Backtrace;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;
use std::{io, mem, panic};

use clap::Parser;
use clarity::types::chainstate::StacksBlockId;
use clarity::types::sqlite::NO_PARAMS;
use clarity::util::log::INJECTED_LOGGER;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::Connection;
use slog::Drain;
use stackslib::chainstate::burn::db::sortdb::{SortitionDB, get_ancestor_sort_id};
use stackslib::chainstate::coordinator::OnChainRewardSetProvider;
use stackslib::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stackslib::chainstate::stacks::Error;
use stackslib::chainstate::stacks::db::StacksChainState;
use stackslib::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stackslib::config::{Config, DEFAULT_MAINNET_CONFIG};

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the stacks chain database
    database_path: PathBuf,
    /// Block to start replay from
    start_block: u64,
    /// Block to end replay on
    end_block: u64,
    /// Database to output to. Defaults to `replay` within `database_path`
    #[arg(long)]
    replay_path: Option<PathBuf>,
}

fn main() {
    if let Err(err) = inner_main() {
        eprintln!("ERROR: {err}");
    }
}

fn inner_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.start_block > cli.end_block {
        panic!(
            "start block {} larger than end block {}",
            cli.start_block, cli.end_block
        );
    }

    validate_blocks(cli)
}

static BACKTRACE: Mutex<String> = Mutex::new(String::new());
static LOGSTRING: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogString;

impl Write for LogString {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        LOGSTRING.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        LOGSTRING.lock().unwrap().flush()
    }
}

impl LogString {
    fn clear() -> String {
        let mut logstring = LOGSTRING.lock().unwrap();
        let mut string = Vec::new();
        mem::swap(&mut *logstring, &mut string);
        String::from_utf8(string).expect("Expected strings to be written to logs")
    }
}

fn validate_blocks(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // panic information along with a backtrace on a panic available in `BACKTRACE`
    panic::set_hook(Box::new(|panic_info| {
        *BACKTRACE.lock().unwrap() = format!("{panic_info}\n{}", Backtrace::force_capture());
    }));

    // inject a logger to capture `slog` logs
    let decorator = slog_term::PlainSyncDecorator::new(LogString);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let logger = slog::Logger::root(drain, slog::o!());
    *INJECTED_LOGGER.lock().unwrap() = Some(logger);

    let db_path = cli.database_path.display().to_string();
    let replay_db_path = cli.replay_path.map_or_else(
        || format!("{db_path}/replay/"),
        |path| path.display().to_string(),
    );

    let (chainstate, _) = StacksChainState::open(
        DEFAULT_MAINNET_CONFIG.is_mainnet(),
        DEFAULT_MAINNET_CONFIG.burnchain.chain_id,
        &format!("{db_path}/chainstate/"),
        None,
    )?;

    let chainstate_conn = chainstate.nakamoto_blocks_db();
    let result_conn = Connection::open(replay_db_path)?;

    let mut count_stmt = chainstate_conn.prepare(&format!(
        "SELECT COUNT(*) \
         FROM   nakamoto_staging_blocks \
         WHERE  orphaned = 0 \
         AND    height BETWEEN {} AND {}",
        cli.start_block, cli.end_block
    ))?;
    let mut block_stmt = chainstate_conn.prepare(&format!(
        "SELECT index_block_hash, height \
         FROM   nakamoto_staging_blocks \
         WHERE  orphaned = 0 \
         AND    height BETWEEN {} AND {}",
        cli.start_block, cli.end_block
    ))?;
    result_conn.execute(
        &format!(
            "CREATE TABLE IF NOT EXISTS replays ( \
                block_hash   TEXT    NOT NULL, \
                block_height INTEGER NOT NULL, \
                timestamp    INTEGER NOT NULL, \
                logs         TEXT    NOT NULL, \
                error        TEXT, \
                PRIMARY KEY  (block_hash, block_height)
            )"
        ),
        NO_PARAMS,
    )?;
    let mut insert_stmt = result_conn.prepare(&format!(
        "INSERT OR REPLACE INTO replays \
         (block_hash, block_height, timestamp, logs, error) \
         VALUES \
         (?1, ?2, ?3, ?4, ?5)"
    ))?;

    let block_count: u64 = count_stmt.query_row(NO_PARAMS, |row| row.get(0))?;
    let bar = ProgressBar::new(block_count);
    let bar = bar.with_style(
        ProgressStyle::with_template("[{elapsed_precise}] {wide_bar} {pos}/{len} [{eta_precise}]")
            .unwrap(),
    );

    let mut blocks = block_stmt.query(NO_PARAMS)?;

    while let Some(row) = blocks.next()? {
        let block_hash: String = row.get(0)?;
        let block_height: u64 = row.get(1)?;

        let result = panic::catch_unwind(|| {
            replay_staging_block(&db_path, &block_hash, &DEFAULT_MAINNET_CONFIG)
                .map_err(|err| format!("error: {err}"))
        })
        .map_err(|_err| {
            let mut backtrace_lock = BACKTRACE.lock().unwrap();
            let mut backtrace = String::new();
            mem::swap(&mut *backtrace_lock, &mut backtrace);
            format!("panic: {backtrace}")
        })
        .flatten();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        insert_stmt.execute((
            block_hash,
            block_height,
            timestamp,
            LogString::clear(),
            result.err(),
        ))?;

        bar.inc(1);
    }

    bar.finish();

    Ok(())
}

fn replay_staging_block(
    db_path: &str,
    index_block_hash_hex: &str,
    conf: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let block_id = StacksBlockId::from_hex(index_block_hash_hex).unwrap();
    let chain_state_path = format!("{db_path}/chainstate/");
    let sort_db_path = format!("{db_path}/burnchain/sortition");

    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap();

    let burnchain = conf.get_burnchain();
    let epochs = conf.burnchain.get_epoch_list();
    let mut sortdb = SortitionDB::connect(
        &sort_db_path,
        burnchain.first_block_height,
        &burnchain.first_block_hash,
        u64::from(burnchain.first_block_timestamp),
        &epochs,
        burnchain.pox_constants.clone(),
        None,
        true,
    )
    .unwrap();

    let (block, block_size) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(&block_id)
        .unwrap()
        .unwrap();
    replay_block_nakamoto(&mut sortdb, &mut chainstate, &block, block_size)?;

    Ok(())
}

#[allow(clippy::result_large_err)]
fn replay_block_nakamoto(
    sort_db: &mut SortitionDB,
    stacks_chain_state: &mut StacksChainState,
    block: &NakamotoBlock,
    block_size: u64,
) -> Result<(), Error> {
    // find corresponding snapshot
    let next_ready_block_snapshot =
        SortitionDB::get_block_snapshot_consensus(sort_db.conn(), &block.header.consensus_hash)?
            .unwrap_or_else(|| {
                panic!(
                    "CORRUPTION: staging Nakamoto block {}/{} does not correspond to a burn block",
                    &block.header.consensus_hash,
                    &block.header.block_hash()
                )
            });

    info!("Process staging Nakamoto block";
           "consensus_hash" => %block.header.consensus_hash,
           "stacks_block_hash" => %block.header.block_hash(),
           "stacks_block_id" => %block.header.block_id(),
           "burn_block_hash" => %next_ready_block_snapshot.burn_header_hash
    );

    let Some(mut expected_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
        stacks_chain_state.db(),
        &block.header.block_id(),
    )
    .unwrap() else {
        error!("Failed to find cost for block {}", block.header.block_id());
        return Ok(());
    };

    let expected_cost = if block.get_tenure_tx_payload().is_some() {
        expected_total_tenure_cost
    } else {
        let Some(expected_parent_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
            stacks_chain_state.db(),
            &block.header.parent_block_id,
        )
        .unwrap() else {
            error!(
                "Failed to find cost for parent of block {}",
                block.header.block_id()
            );
            return Ok(());
        };
        expected_total_tenure_cost.sub(&expected_parent_total_tenure_cost).expect("FATAL: failed to subtract parent total cost from self total cost in non-tenure-changing block");
        expected_total_tenure_cost
    };

    let elected_height = sort_db
        .get_consensus_hash_height(&block.header.consensus_hash)?
        .ok_or_else(|| Error::NoSuchBlockError)?;
    let elected_in_cycle = sort_db
        .pox_constants
        .block_height_to_reward_cycle(sort_db.first_block_height, elected_height)
        .ok_or_else(|| {
            Error::InvalidStacksBlock("Elected in block height before first_block_height".into())
        })?;
    let active_reward_set = OnChainRewardSetProvider::<DummyEventDispatcher>(None)
        .read_reward_set_nakamoto_of_cycle(
            elected_in_cycle,
            stacks_chain_state,
            sort_db,
            &block.header.parent_block_id,
            true,
        )
        .map_err(|e| {
            warn!(
                "Cannot process Nakamoto block: could not load reward set that elected the block";
                "err" => ?e,
                "consensus_hash" => %block.header.consensus_hash,
                "stacks_block_hash" => %block.header.block_hash(),
                "stacks_block_id" => %block.header.block_id(),
                "parent_block_id" => %block.header.parent_block_id,
            );
            Error::NoSuchBlockError
        })?;
    let (mut chainstate_tx, clarity_instance) = stacks_chain_state.chainstate_tx_begin()?;

    let Some(parent_header_info) =
        NakamotoChainState::get_block_header(&chainstate_tx.tx, &block.header.parent_block_id)?
    else {
        info!("Cannot process Nakamoto block: missing parent header";
               "consensus_hash" => %block.header.consensus_hash,
               "stacks_block_hash" => %block.header.block_hash(),
               "stacks_block_id" => %block.header.block_id(),
               "parent_block_id" => %block.header.parent_block_id
        );
        return Ok(());
    };

    let parent_block_id = StacksBlockId::new(
        &parent_header_info.consensus_hash,
        &parent_header_info.anchored_header.block_hash(),
    );
    if parent_block_id != block.header.parent_block_id {
        drop(chainstate_tx);

        let msg = "Discontinuous Nakamoto Stacks block";
        warn!("{}", &msg;
              "child parent_block_id" => %block.header.parent_block_id,
              "expected parent_block_id" => %parent_block_id,
              "consensus_hash" => %block.header.consensus_hash,
              "stacks_block_hash" => %block.header.block_hash(),
              "stacks_block_id" => %block.header.block_id()
        );
        return Err(Error::InvalidStacksBlock(msg.into()));
    }

    let burnchain_view = if let Some(tenure_change) = block.get_tenure_tx_payload() {
        if let Some(ref parent_burn_view) = parent_header_info.burn_view {
            // check that the tenure_change's burn view descends from the parent
            let parent_burn_view_sn = SortitionDB::get_block_snapshot_consensus(
                sort_db.conn(),
                parent_burn_view,
            )?
            .ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                Error::InvalidStacksBlock("Failed to load burn view of parent block ID".into())
            })?;
            let handle = sort_db.index_handle_at_ch(&tenure_change.burn_view_consensus_hash)?;
            let connected_sort_id = get_ancestor_sort_id(
                &handle,
                parent_burn_view_sn.block_height,
                &handle.context.chain_tip,
            )?
            .ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                Error::InvalidStacksBlock("Failed to load burn view of parent block ID".into())
            })?;
            if connected_sort_id != parent_burn_view_sn.sortition_id {
                warn!(
                    "Cannot process Nakamoto block: parent block's burnchain view does not connect to own burn view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                return Err(Error::InvalidStacksBlock(
                    "Does not connect to burn view of parent block ID".into(),
                ));
            }
        }
        &tenure_change.burn_view_consensus_hash
    } else {
        parent_header_info.burn_view.as_ref().ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: parent block does not have a burnchain view and current block has no tenure tx";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                Error::InvalidStacksBlock("Failed to load burn view of parent block ID".into())
            })?
    };
    let Some(burnchain_view_sn) =
        SortitionDB::get_block_snapshot_consensus(sort_db.conn(), burnchain_view)?
    else {
        warn!(
            "Cannot process Nakamoto block: failed to find Sortition ID associated with burnchain view";
            "consensus_hash" => %block.header.consensus_hash,
            "stacks_block_hash" => %block.header.block_hash(),
            "stacks_block_id" => %block.header.block_id(),
            "burn_view_consensus_hash" => %burnchain_view,
        );
        return Ok(());
    };

    let new_tenure = block.is_wellformed_tenure_start_block()?;
    let (commit_burn, sortition_burn) = if new_tenure {
        let block_commit = SortitionDB::get_block_commit(
            sort_db.conn(),
            &next_ready_block_snapshot.winning_block_txid,
            &next_ready_block_snapshot.sortition_id,
        )?
        .expect("FATAL: no block-commit for tenure-start block");

        let sort_burn =
            SortitionDB::get_block_burn_amount(sort_db.conn(), &next_ready_block_snapshot)?;
        (block_commit.burn_fee, sort_burn)
    } else {
        (0, 0)
    };

    let pox_constants = sort_db.pox_constants.clone();

    let block_id = block.block_id();
    let mut burn_view_handle = sort_db.index_handle(&burnchain_view_sn.sortition_id);
    let (ok_opt, err_opt) = match NakamotoChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut burn_view_handle,
        burnchain_view,
        &pox_constants,
        &parent_header_info,
        &next_ready_block_snapshot.burn_header_hash,
        next_ready_block_snapshot
            .block_height
            .try_into()
            .expect("Failed to downcast u64 to u32"),
        next_ready_block_snapshot.burn_header_timestamp,
        block,
        block_size,
        commit_burn,
        sortition_burn,
        &active_reward_set,
        true,
    ) {
        Ok((receipt, _, _, _)) => (Some(receipt), None),
        Err(e) => (None, Some(e)),
    };

    if let Some(receipt) = ok_opt {
        let evaluated_cost = receipt.anchored_block_cost.clone();
        if evaluated_cost != expected_cost {
            error!(
                "Failed processing block! block = {block_id}. Unexpected cost. expected = {expected_cost}, evaluated = {evaluated_cost}"
            );
            return Err(Error::BlockCostMismatch(expected_cost, evaluated_cost));
        }
    }

    if let Some(e) = err_opt {
        drop(chainstate_tx);

        warn!(
            "Failed to append {}/{}: {:?}",
            &block.header.consensus_hash,
            &block.header.block_hash(),
            &e;
            "stacks_block_id" => %block.header.block_id()
        );

        return Err(e);
    };

    Ok(())
}
