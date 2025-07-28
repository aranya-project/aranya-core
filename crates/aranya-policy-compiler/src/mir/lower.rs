use std::collections::HashMap;

use slotmap::SlotMap;

use crate::{
    hir::{
        ActionArg, ActionDef, ActionId, CmdDef, CmdField, CmdFieldKind, CmdId, EffectDef,
        EffectField, EffectFieldId, EffectFieldKind, EffectId, EnumDef, EnumId, Expr, ExprId,
        ExprKind, FactDef, FactField, FactId, FactKey, FactLiteral, FactVal, FinishFuncArg,
        FinishFuncDef, FinishFuncId, FuncArg, FuncDef, FuncId, GlobalId, GlobalLetDef, Hir, Ident,
        IdentId, InternalFunction, MatchPattern, Stmt, StmtId, StmtKind, StructDef, StructField,
        StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind, Visitor,
    },
    mir::ssa::{Block, BlockId, Inst, Terminator, ValueId},
};

#[derive(Clone, Debug)]
pub(crate) struct LowerCtx<'hir> {
    hir: &'hir Hir,
    blocks: SlotMap<BlockId, Block>,
    current_block: BlockId,
    next_value: usize,
    break_targets: Vec<BlockId>,
    continue_targets: Vec<BlockId>,
    env: Vec<HashMap<IdentId, ValueId>>,
}

impl<'hir> LowerCtx<'hir> {
    fn new(hir: &'hir Hir) -> Self {
        let mut blocks = SlotMap::with_key();
        let current_block = blocks.insert_with_key(|id| Block {
            id,
            instr: Vec::new(),
            term: None,
        });
        Self {
            hir,
            blocks,
            current_block,
            next_value: 0,
            break_targets: Vec::new(),
            continue_targets: Vec::new(),
            env: vec![HashMap::new()],
        }
    }

    fn new_block(&mut self) -> BlockId {
        self.blocks.insert_with_key(|id| Block {
            id,
            instr: Vec::new(),
            term: None,
        })
    }

    fn new_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        id
    }

    fn emit(&mut self, instr: Inst) {
        let block = &mut self.blocks[self.current_block];
        block.instr.push(instr);
    }

    fn terminate(&mut self, term: Terminator) {
        let block = &mut self.blocks[self.current_block];
        assert!(block.term.is_none());
        block.term = Some(term);
    }

    fn set_current(&mut self, block: BlockId) {
        self.current_block = block;
    }

    fn push_scope(&mut self) {
        self.env.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.env.pop();
    }

    fn bind(&mut self, ident: IdentId, val: ValueId) {
        self.env.last_mut().unwrap().insert(ident, val);
    }
}

impl<'hir> Visitor<'hir> for LowerCtx<'hir> {
    type Result = ();

    fn visit_action_def(&mut self, def: &ActionDef) -> Self::Result {
        self.push_scope();

        let action_id = def.id;
        let block = self.new_block();
        self.set_current(block);

        // TODO: Handle action arguments properly
        // for arg in &def.args {
        //     let value = self.new_value();
        //     self.emit(Inst::Arg(value, arg.id));
        // }

        let block = self.hir.blocks.get(def.block).unwrap();
        for _ in &block.stmts {}

        let ret_value = self.new_value();
        self.terminate(Terminator::Return(ret_value));

        ()
    }
}
