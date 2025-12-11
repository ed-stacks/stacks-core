use std::collections::HashMap;

use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::StacksEpochId;
use clarity::vm::contexts::{CallStack, GlobalContext};
use clarity::vm::contracts::Contract;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::{ClarityDatabase, MemoryBackingStore};
use clarity::vm::errors::{CheckErrors, Error};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
};
use clarity::vm::wasm::compile;
use clarity::vm::wasm::datastore::{BurnDatastore, StacksConstants};
use clarity::vm::wasm::initialize::initialize_contract;
use clarity::vm::wasm::tools::execute;
use clarity::vm::wasm::wasm_utils::call_function;
use clarity::vm::{ClarityVersion, ContractContext, Value};

#[macro_use]
mod lib_tests;

//
// Boot contracts tests
//

// signers.clar

test_multi_contract_call_response!(
    test_get_signer_by_index,
    ["boot-contracts/signers", "boot-contracts/signers-caller"],
    "signers-caller",
    "get-signer-by-index",
    |response: ResponseData| {
        assert!(!response.committed);
        assert_eq!(*response.data, Value::UInt(2));
    }
);

test_multi_contract_call_response!(
    test_get_last_set_cycle,
    ["boot-contracts/signers", "boot-contracts/signers-caller"],
    "signers-caller",
    "get-last-set-cycle",
    |response: ResponseData| {
        assert!(response.committed);
        assert_eq!(*response.data, Value::UInt(0));
    }
);
