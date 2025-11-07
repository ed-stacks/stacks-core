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

use std::process;
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::sqlite::NO_PARAMS;
use stackslib::chainstate::burn::db::sortdb::{SortitionDB, get_ancestor_sort_id};
use stackslib::chainstate::coordinator::OnChainRewardSetProvider;
use stackslib::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stackslib::chainstate::stacks::Error as ChainstateError;
use stackslib::chainstate::stacks::db::StacksChainState;
use stackslib::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stackslib::config::Config;

pub fn command_bench(
    chain_db: String,
    bench_db: String,
    start_block: u64,
    end_block: u64,
    conf: Config,
) -> Result<(), ChainstateError> {
    let start = Instant::now();

    let chain_state_path = format!("{chain_db}/chainstate/");

    let (chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )?;

    let conn = chainstate.nakamoto_blocks_db();

    let query = format!(
        "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 ORDER BY height ASC LIMIT {start_block}, {}",
        end_block.saturating_sub(start_block)
    );

    let mut stmt = conn.prepare(&query)?;
    let mut hashes_set = stmt.query(NO_PARAMS)?;

    let mut index_block_hashes: Vec<String> = vec![];
    while let Ok(Some(row)) = hashes_set.next() {
        index_block_hashes.push(row.get(0)?);
    }

    let total = index_block_hashes.len();
    println!("Will check {total} blocks");
    for (i, index_block_hash) in index_block_hashes.iter().enumerate() {
        if i % 100 == 0 {
            println!("Checked {i}...");
        }
        replay_naka_staging_block(&chain_db, index_block_hash, &conf)?;
    }
    println!("Finished. run_time_seconds = {}", start.elapsed().as_secs());

    Ok(())
}

/// Fetch and process a NakamotoBlock from database and call `replay_block_nakamoto()` to validate
fn replay_naka_staging_block(
    db_path: &str,
    index_block_hash_hex: &str,
    conf: &Config,
) -> Result<(), ChainstateError> {
    let block_id = StacksBlockId::from_hex(index_block_hash_hex).unwrap();
    let chain_state_path = format!("{db_path}/chainstate/");
    let sort_db_path = format!("{db_path}/burnchain/sortition");

    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )?;

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
    )?;

    let (block, block_size) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(&block_id)?
        .unwrap();

    replay_block_nakamoto(&mut sortdb, &mut chainstate, &block, block_size)?;

    Ok(())
}

fn replay_block_nakamoto(
    sort_db: &mut SortitionDB,
    stacks_chain_state: &mut StacksChainState,
    block: &NakamotoBlock,
    block_size: u64,
) -> Result<(), ChainstateError> {
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

    let Some(mut expected_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
        stacks_chain_state.db(),
        &block.header.block_id(),
    )?
    else {
        println!("Failed to find cost for block {}", block.header.block_id());
        return Ok(());
    };

    let expected_cost = if block.get_tenure_tx_payload().is_some() {
        expected_total_tenure_cost
    } else {
        let Some(expected_parent_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
            stacks_chain_state.db(),
            &block.header.parent_block_id,
        )?
        else {
            println!(
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
        .ok_or_else(|| ChainstateError::NoSuchBlockError)?;
    let elected_in_cycle = sort_db
        .pox_constants
        .block_height_to_reward_cycle(sort_db.first_block_height, elected_height)
        .ok_or_else(|| {
            ChainstateError::InvalidStacksBlock(
                "Elected in block height before first_block_height".into(),
            )
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
            eprintln!(
                "Cannot process Nakamoto block: could not load reward set that elected the block"
            );
            eprintln!("error: {:?}", e);
            eprintln!("consensus_hash: {}", block.header.consensus_hash);
            eprintln!("stacks_block_hash: {}", block.header.block_hash());
            eprintln!("stacks_block_id: {}", block.header.block_id());
            eprintln!("parent_block_id: {}", block.header.parent_block_id);
            ChainstateError::NoSuchBlockError
        })?;
    let (mut chainstate_tx, clarity_instance) = stacks_chain_state.chainstate_tx_begin()?;

    // find parent header
    let Some(parent_header_info) =
        NakamotoChainState::get_block_header(&chainstate_tx.tx, &block.header.parent_block_id)?
    else {
        // no parent; cannot process yet
        eprintln!("Cannot process Nakamoto block: missing parent header");
        eprintln!("consensus_hash: {}", block.header.consensus_hash);
        eprintln!("stacks_block_hash: {}", block.header.block_hash());
        eprintln!("stacks_block_id: {}", block.header.block_id());
        eprintln!("parent_block_id: {}", block.header.parent_block_id);
        return Ok(());
    };

    // sanity check -- must attach to parent
    let parent_block_id = StacksBlockId::new(
        &parent_header_info.consensus_hash,
        &parent_header_info.anchored_header.block_hash(),
    );
    if parent_block_id != block.header.parent_block_id {
        drop(chainstate_tx);

        let msg = "Discontinuous Nakamoto Stacks block";
        eprintln!("{msg}");
        eprintln!("child parent_block_id: {}", block.header.parent_block_id);
        eprintln!("expected parent_block_id: {}", parent_block_id);
        eprintln!("consensus_hash: {}", block.header.consensus_hash);
        eprintln!("stacks_block_hash: {}", block.header.block_hash());
        eprintln!("stacks_block_id: {}", block.header.block_id());
        return Err(ChainstateError::InvalidStacksBlock(msg.into()));
    }

    // set the sortition handle's pointer to the block's burnchain view.
    //   this is either:
    //    (1)  set by the tenure change tx if one exists
    //    (2)  the same as parent block id

    let burnchain_view = if let Some(tenure_change) = block.get_tenure_tx_payload() {
        if let Some(ref parent_burn_view) = parent_header_info.burn_view {
            // check that the tenure_change's burn view descends from the parent
            let parent_burn_view_sn = SortitionDB::get_block_snapshot_consensus(
                sort_db.conn(),
                parent_burn_view,
            )?
            .ok_or_else(|| {
                eprintln!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view"
                );
                eprintln!("consensus_hash: {}", block.header.consensus_hash);
                eprintln!("stacks_block_hash: {}", block.header.block_hash());
                eprintln!("stacks_block_id: {}", block.header.block_id());
                eprintln!("parent_block_id: {}", block.header.parent_block_id);
                ChainstateError::InvalidStacksBlock(
                    "Failed to load burn view of parent block ID".into(),
                )
            })?;
            let handle = sort_db.index_handle_at_ch(&tenure_change.burn_view_consensus_hash)?;
            let connected_sort_id = get_ancestor_sort_id(
                &handle,
                parent_burn_view_sn.block_height,
                &handle.context.chain_tip,
            )?
            .ok_or_else(|| {
                eprintln!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view"
                );
                eprintln!("consensus_hash: {}", block.header.consensus_hash);
                eprintln!("stacks_block_hash: {}", block.header.block_hash());
                eprintln!("stacks_block_id: {}", block.header.block_id());
                eprintln!("parent_block_id: {}", block.header.parent_block_id);
                ChainstateError::InvalidStacksBlock(
                    "Failed to load burn view of parent block ID".into(),
                )
            })?;
            if connected_sort_id != parent_burn_view_sn.sortition_id {
                eprintln!(
                    "Cannot process Nakamoto block: parent block's burnchain view does not connect to own burn view"
                );
                eprintln!("consensus_hash: {}", block.header.consensus_hash);
                eprintln!("stacks_block_hash: {}", block.header.block_hash());
                eprintln!("stacks_block_id: {}", block.header.block_id());
                eprintln!("parent_block_id: {}", block.header.parent_block_id);
                return Err(ChainstateError::InvalidStacksBlock(
                    "Does not connect to burn view of parent block ID".into(),
                ));
            }
        }
        &tenure_change.burn_view_consensus_hash
    } else {
        parent_header_info.burn_view.as_ref().ok_or_else(|| {
                eprintln!(
                    "Cannot process Nakamoto block: parent block does not have a burnchain view and current block has no tenure tx"
                );
                eprintln!("consensus_hash: {}", block.header.consensus_hash);
                eprintln!("stacks_block_hash: {}", block.header.block_hash());
                eprintln!("stacks_block_id: {}", block.header.block_id());
                eprintln!("parent_block_id: {}", block.header.parent_block_id);
                ChainstateError::InvalidStacksBlock("Failed to load burn view of parent block ID".into())
            })?
    };
    let Some(burnchain_view_sn) =
        SortitionDB::get_block_snapshot_consensus(sort_db.conn(), burnchain_view)?
    else {
        // This should be checked already during block acceptance and parent block processing
        //   - The check for expected burns returns `NoSuchBlockError` if the burnchain view
        //      could not be found for a block with a tenure tx.
        // We error here anyways, but the check during block acceptance makes sure that the staging
        //  db doesn't get into a situation where it continuously tries to retry such a block (because
        //  such a block shouldn't land in the staging db).
        eprintln!(
            "Cannot process Nakamoto block: failed to find Sortition ID associated with burnchain view"
        );
        eprintln!("consensus_hash: {}", block.header.consensus_hash);
        eprintln!("stacks_block_hash: {}", block.header.block_hash());
        eprintln!("stacks_block_id: {}", block.header.block_id());
        eprintln!("burn_view_consensus_hash: {}", burnchain_view);
        return Ok(());
    };

    // find commit and sortition burns if this is a tenure-start block
    let new_tenure = block.is_wellformed_tenure_start_block()?;
    let (commit_burn, sortition_burn) = if new_tenure {
        // find block-commit to get commit-burn
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

    // attach the block to the chain state and calculate the next chain tip.
    let pox_constants = sort_db.pox_constants.clone();

    // NOTE: because block status is updated in a separate transaction, we need `chainstate_tx`
    // and `clarity_instance` to go out of scope before we can issue the it (since we need a
    // mutable reference to `stacks_chain_state` to start it).  This means ensuring that, in the
    // `Ok(..)` case, the `clarity_commit` gets dropped beforehand.  In order to do this, we first
    // run `::append_block()` here, and capture both the Ok(..) and Err(..) results as
    // Option<..>'s.  Then, if we errored, we can explicitly drop the `Ok(..)` option (even
    // though it will always be None), which gets the borrow-checker to believe that it's safe
    // to access `stacks_chain_state` again.  In the `Ok(..)` case, it's instead sufficient so
    // simply commit the block before beginning the second transaction to mark it processed.
    let block_id = block.block_id();
    let mut burn_view_handle = sort_db.index_handle(&burnchain_view_sn.sortition_id);
    let (ok_opt, err_opt) = match NakamotoChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut burn_view_handle,
        &burnchain_view,
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
        // check the cost
        let evaluated_cost = receipt.anchored_block_cost.clone();
        if evaluated_cost != expected_cost {
            println!(
                "Failed processing block! block = {block_id}. Unexpected cost. expected = {expected_cost}, evaluated = {evaluated_cost}"
            );
            process::exit(1);
        }
    }

    if let Some(e) = err_opt {
        // force rollback
        drop(chainstate_tx);

        eprintln!(
            "Failed to append {}/{}: {:?}",
            block.header.consensus_hash,
            block.header.block_hash(),
            e,
        );
        eprintln!("stacks_block_id: {}", block.header.block_id());

        // as a separate transaction, mark this block as processed and orphaned.
        // This is done separately so that the staging blocks DB, which receives writes
        // from the network to store blocks, will be available for writes while a block is
        // being processed. Therefore, it's *very important* that block-processing happens
        // within the same, single thread.  Also, it's *very important* that this update
        // succeeds, since *we have already processed* the block.
        return Err(e);
    };

    Ok(())
}
