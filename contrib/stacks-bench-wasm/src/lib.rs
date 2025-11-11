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

mod db;
mod plot;

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::sqlite::NO_PARAMS;
use stackslib::chainstate::burn::db::sortdb::{SortitionDB, get_ancestor_sort_id};
use stackslib::chainstate::coordinator::OnChainRewardSetProvider;
use stackslib::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stackslib::chainstate::stacks::db::StacksChainState;
use stackslib::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stackslib::chainstate::stacks::{
    Error as ChainstateError, StacksTransaction, TransactionPayload,
};
use stackslib::clarity::vm::analysis::types::ContractAnalysis;
use stackslib::clarity::vm::clarity::ClarityConnection;
use stackslib::clarity::vm::contracts::Contract;
use stackslib::clarity::vm::database::ClaritySerializable;
use stackslib::clarity::vm::database::clarity_db::ContractDataVarName;
use stackslib::clarity::vm::diagnostic::DiagnosableError;
use stackslib::clarity::vm::errors::{Error as clarity_error, WasmError};
use stackslib::clarity::vm::types::QualifiedContractIdentifier;
use stackslib::clarity_vm::database::HeadersDBConn;
use stackslib::config::Config;

use db::BenchDatabase;

pub fn command_graph(
    bench_db: String,
    path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bench_db = BenchDatabase::open(bench_db)?;
    plot::write_plot(&mut bench_db, path)?;
    Ok(())
}

pub fn command_bench(
    chain_db: String,
    bench_db: String,
    start_block: u64,
    end_block: u64,
    conf: Config,
) -> Result<(), ChainstateError> {
    let mut bench_db = BenchDatabase::open(bench_db)?;

    let chain_state_path = format!("{chain_db}/chainstate/");

    let (chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )?;

    let conn = chainstate.nakamoto_blocks_db();

    let query = format!(
        "SELECT index_block_hash \
         FROM nakamoto_staging_blocks \
         WHERE orphaned = 0 \
           AND height BETWEEN {start_block} and {end_block}"
    );

    let mut stmt = conn.prepare(&query)?;
    let mut hashes_set = stmt.query(NO_PARAMS)?;

    let mut index_block_hashes: Vec<String> = vec![];
    while let Ok(Some(row)) = hashes_set.next() {
        index_block_hashes.push(row.get(0)?);
    }

    let mut curr_block = 1;
    let n_blocks = index_block_hashes.len();

    for block_hash in index_block_hashes {
        println!("Processing {curr_block}/{n_blocks}");
        let bench = replay_naka_staging_block(&chain_db, block_hash, &conf)?;
        bench_db.insert_bench(&bench)?;
        curr_block += 1;
    }

    Ok(())
}

pub fn command_compile(
    chain_db: String,
    start_height: u64,
    end_height: u64,
    conf: Config,
) -> Result<(), ChainstateError> {
    if start_height > end_height {
        return Err(ChainstateError::InvalidStacksBlock(
            "start height greater than end height".into(),
        ));
    }

    command_compile_impl(chain_db, start_height, end_height, conf)
}
/// Fetch and process a NakamotoBlock from database and call `replay_block_nakamoto()` to validate
fn replay_naka_staging_block(
    db_path: &str,
    block_hash: String,
    conf: &Config,
) -> Result<db::Bench, ChainstateError> {
    let block_id = StacksBlockId::from_hex(&block_hash).unwrap();
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

    let start = Instant::now();
    let error = replay_block_nakamoto(&mut sortdb, &mut chainstate, &block, block_size)
        .err()
        .map(|err| err.to_string());
    let runtime = start.elapsed().as_nanos();

    let calls = block.txs.iter().fold(0, |calls, tx| match &tx.payload {
        TransactionPayload::ContractCall(_) => calls + 1,
        _ => calls,
    });

    Ok(db::Bench {
        block_hash,
        wasm: cfg!(feature = "clarity-wasm"),
        runtime: runtime.try_into().expect("nanosecond precision overflow"),
        calls,
        error,
    })
}

fn load_block_transactions(
    chainstate: &mut StacksChainState,
    block_id: &StacksBlockId,
    consensus_hash: &ConsensusHash,
    block_hash: &BlockHeaderHash,
) -> Result<Vec<StacksTransaction>, ChainstateError> {
    // Prefer the already-materialized Nakamoto block entry.  Fallback to
    // loading from disk if the block was not cached in the MARF staging table.
    if let Some((nakamoto_block, _)) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(block_id)?
    {
        Ok(nakamoto_block.txs)
    } else {
        let blocks_path = chainstate.blocks_path.clone();
        let maybe_block = StacksChainState::load_block(&blocks_path, consensus_hash, block_hash)?;
        if let Some(block) = maybe_block {
            Ok(block.txs)
        } else {
            Err(ChainstateError::NoSuchBlockError)
        }
    }
}

/// Outcome of attempting to compile a contract for a block range.
#[derive(Debug, PartialEq, Eq)]
enum ContractCompileOutcome {
    /// The contract already had a WASM module stored alongside it.
    AlreadyCompiled,
    /// The contract has been successfully compiled and persisted.
    Compiled,
    /// The contract could not be found in chainstate at this height.
    Missing,
}

fn ensure_contract_compiled(
    chainstate: &mut StacksChainState,
    sortdb: &mut SortitionDB,
    block_id: &StacksBlockId,
    contract_id: &QualifiedContractIdentifier,
) -> Result<ContractCompileOutcome, ChainstateError> {
    let sort_handle = sortdb.index_handle_at_tip();

    // Pull the immutable snapshot for this block so we can see the contract
    // exactly as it existed when the block executed.  If the contract is
    // missing or already has a WASM module there is nothing to do.
    let maybe_plan = chainstate.with_read_only_clarity_tx(&sort_handle, block_id, |conn| {
        gather_compile_plan(conn, contract_id)
    });

    let Some(plan_result) = maybe_plan else {
        return Ok(ContractCompileOutcome::Missing);
    };

    match plan_result? {
        None => Ok(ContractCompileOutcome::AlreadyCompiled),
        Some(plan) => {
            persist_compiled_contract(chainstate, sortdb, contract_id, plan)?;
            Ok(ContractCompileOutcome::Compiled)
        }
    }
}

struct CompilePlan {
    contract: Contract,
    analysis: ContractAnalysis,
}

/// Collect the serialized contract and its stored analysis so we can rebuild
/// the WASM module. Returns `None` if we cannot (or should not) compile.
fn gather_compile_plan(
    conn: &mut impl ClarityConnection,
    contract_id: &QualifiedContractIdentifier,
) -> Result<Option<CompilePlan>, ChainstateError> {
    let epoch = conn.get_epoch();

    let contract = conn.with_clarity_db_readonly(|db| db.get_contract(contract_id))?;

    if contract.contract_context.wasm_module.is_some() {
        return Ok(None);
    }

    let analysis = conn.with_clarity_db_readonly(|db| db.load_contract_analysis(contract_id))?;
    let Some(analysis) = analysis else {
        return Err(ChainstateError::InvalidStacksBlock(
            format!("Missing analysis for contract {}", contract_id).into(),
        ));
    };

    // The stored analysis may have been generated under an earlier epoch.
    // Re-canonicalize so the regenerated WASM matches the metadata format that
    // nodes expect when they read it back out of the DB.
    let mut analysis = analysis;
    analysis.canonicalize_types(&epoch);

    Ok(Some(CompilePlan { contract, analysis }))
}

fn persist_compiled_contract(
    chainstate: &mut StacksChainState,
    sortdb: &mut SortitionDB,
    contract_id: &QualifiedContractIdentifier,
    mut plan: CompilePlan,
) -> Result<(), ChainstateError> {
    let mut wasm_module = clar2wasm::compile_contract(plan.analysis.clone()).map_err(|e| {
        ChainstateError::ClarityError(
            clarity_error::Wasm(WasmError::WasmGeneratorError(e.message())).into(),
        )
    })?;

    plan.contract
        .contract_context
        .set_wasm_module(wasm_module.emit_wasm());

    // Convert contract to serialized form
    let serialized_contract = plan.contract.serialize();

    // Open a scoped Clarity transaction so we can reuse the same metadata write
    // paths as block processing. We intentionally avoid advancing the block
    // tip; this only mutates the side-store entry for the contract.
    let headers_conn = HeadersDBConn(chainstate.index_conn());
    let sort_handle = sortdb.index_handle_at_tip();
    let tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())?;
    let current_tip = StacksBlockId::new(&tip.0, &tip.1);

    let mut clarity_block = chainstate.clarity_state.begin_block(
        &current_tip,
        &current_tip,
        &headers_conn,
        &sort_handle,
    );

    clarity_block.as_transaction(|tx| {
        tx.with_clarity_db(|db| {
            db.set_metadata(
                contract_id,
                ContractDataVarName::Contract.as_str(),
                &serialized_contract,
            )
            .map_err(|e| clarity_error::from(e).into())
        })
    })?;

    Ok(())
}

fn command_compile_impl(
    chain_db: String,
    start_height: u64,
    end_height: u64,
    conf: Config,
) -> Result<(), ChainstateError> {
    let chain_state_path = format!("{chain_db}/chainstate/");
    let sort_db_path = format!("{chain_db}/burnchain/sortition");

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

    let Some(canonical_tip) =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)?
    else {
        return Err(ChainstateError::NoSuchBlockError);
    };

    if end_height > canonical_tip.stacks_block_height {
        return Err(ChainstateError::InvalidStacksBlock(
            format!(
                "end height {} exceeds canonical tip height {}",
                end_height, canonical_tip.stacks_block_height
            )
            .into(),
        ));
    }

    let mut headers =
        StacksChainState::get_ancestors_headers(chainstate.db(), canonical_tip, start_height)?;
    headers.retain(|header| {
        header.stacks_block_height >= start_height && header.stacks_block_height <= end_height
    });
    headers.sort_by_key(|header| header.stacks_block_height);

    let mut compiled_contracts = HashSet::new();
    let mut total_compiled = 0;
    let mut total_seen = 0;

    // Iterate the canonical headers from oldest → newest, reusing a simple map
    // so we never compile the same contract twice.
    for header in headers {
        let block_id = header.index_block_hash();
        let consensus_hash = header.consensus_hash.clone();
        let block_hash = header.anchored_header.block_hash();

        let txs =
            load_block_transactions(&mut chainstate, &block_id, &consensus_hash, &block_hash)?;

        for tx in txs {
            total_seen += 1;

            let TransactionPayload::ContractCall(contract_call) = &tx.payload else {
                continue;
            };

            let contract_id = contract_call.to_clarity_contract_id();
            if compiled_contracts.contains(&contract_id) {
                continue;
            }

            match ensure_contract_compiled(&mut chainstate, &mut sortdb, &block_id, &contract_id)? {
                ContractCompileOutcome::AlreadyCompiled => {
                    compiled_contracts.insert(contract_id);
                }
                ContractCompileOutcome::Compiled => {
                    println!(
                        "Compiled contract {} (height {})",
                        contract_id, header.stacks_block_height
                    );
                    compiled_contracts.insert(contract_id);
                    total_compiled += 1;
                }
                ContractCompileOutcome::Missing => {
                    println!(
                        "Contract {} not found at height {}, skipping",
                        contract_id, header.stacks_block_height
                    );
                }
            }
        }
    }

    println!(
        "Processed {} contract calls, compiled {} contracts",
        total_seen, total_compiled
    );
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
