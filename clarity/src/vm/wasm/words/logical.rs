use super::{SimpleWord, Word};

use crate::vm::types::TypeSignature;
use crate::vm::wasm::cost::WordCharge;
use crate::vm::wasm::wasm_generator::{GeneratorError, WasmGenerator};
use crate::vm::ClarityName;

#[derive(Debug)]
pub struct Not;

impl Word for Not {
    fn name(&self) -> ClarityName {
        "not".into()
    }
}

impl SimpleWord for Not {
    fn visit(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _arg_types: &[TypeSignature],
        _return_type: &TypeSignature,
    ) -> Result<(), GeneratorError> {
        self.charge(generator, builder, 0)?;
        builder.call(generator.func_by_name("stdlib.not"));
        Ok(())
    }
}
