use std::{collections::HashMap, mem};

use slotmap::{SecondaryMap, SlotMap, SparseSecondaryMap};

use crate::{
    hir::{
        self, ActionArg, ActionCall, ActionDef, ActionId, CheckStmt, CmdDef, CmdField,
        CmdFieldKind, CmdId, EffectDef, EffectField, EffectFieldId, EffectFieldKind, EffectId,
        EnumDef, EnumId, Expr, ExprId, ExprKind, FactDef, FactField, FactId, FactKey, FactLiteral,
        FactVal, FinishFuncArg, FinishFuncDef, FinishFuncId, FuncArg, FuncDef, GlobalId,
        GlobalLetDef, Hir, Ident, IdentId, IfBranch, IfStmt, Intrinsic, MapStmt, MatchArm,
        MatchPattern, MatchStmt, NormalizedHir, ReturnStmt, Stmt, StmtId, StmtKind, StructDef,
        StructField, StructFieldId, StructFieldKind, StructId, Ternary, VType, VTypeId, VTypeKind,
    },
    mir::{
        ssa::{
            BinOp, Block, BlockId, Branch, Call, Const, ConstValue, Create, Delete, Emit,
            FactCount, FactCountType, FieldAccess, FieldId, Func, FuncId, Inst, InstKind, Load,
            Phi, Publish, Query, Terminator, UnaryOp, Update, ValueId,
        },
        Mir,
    },
    symbol_resolution::SymbolId,
};

#[derive(Clone, Debug)]
pub(super) struct LowerCtx<'hir> {
    hir: &'hir NormalizedHir,
    // TODO
    pub funcs: SlotMap<FuncId, Func>,
    /// TODO
    pub env: Vec<HashMap<IdentId, ValueId>>,
    /// TODO
    pub value_types: HashMap<ValueId, VTypeId>,
    // // Assume type information is available for each ID type
    // // TODO(eric): Get this from "TypeCheckedHir".
    // pub expr_types: SecondaryMap<ExprId, VTypeId>,
    // pub stmt_types: SecondaryMap<StmtId, VTypeId>,
    // pub action_types: SecondaryMap<ActionId, VTypeId>,
    // pub func_types: SecondaryMap<hir::FuncId, VTypeId>,
    // pub finish_func_types: SecondaryMap<FinishFuncId, VTypeId>,
}

impl<'hir> LowerCtx<'hir> {
    pub fn build(hir: &'hir NormalizedHir) -> Self {
        let mut ctx = Self {
            hir,
            funcs: SlotMap::with_key(),
            env: vec![HashMap::new()],
            value_types: HashMap::new(),
            // expr_types: SecondaryMap::new(),
            // stmt_types: SecondaryMap::new(),
            // action_types: SecondaryMap::new(),
            // func_types: SecondaryMap::new(),
            // finish_func_types: SecondaryMap::new(),
        };
        // TODO: lower
        ctx
    }
}

#[derive(Clone, Debug)]
struct FuncLowerCtx<'hir> {
    hir: &'hir NormalizedHir,
    params: Vec<ValueId>,
    /// All basic blocks.
    blocks: SlotMap<BlockId, Block>,
    /// The current basic block.
    current_block: BlockId,
    /// Instructions keyed by [`ValueId`].
    inst: Vec<Inst>,
    last_value: ValueId,
    /// Maps values to their identifiers.
    env: HashMap<IdentId, ValueId>,

    /// Memoized lowereed HIR blocks.
    lowered_blocks: HashMap<hir::BlockId, (BlockId, ValueId)>,
}

impl<'hir> FuncLowerCtx<'hir> {
    pub(crate) fn new(hir: &'hir NormalizedHir) -> Self {
        let mut blocks = SlotMap::with_key();
        let current_block = blocks.insert_with_key(|id| Block {
            id,
            phi: Vec::new(),
            instr: Vec::new(),
            term: None,
            succ: Vec::new(),
            preds: Vec::new(),
        });
        Self {
            hir,
            params: Vec::new(),
            blocks,
            current_block,
            inst: Vec::new(),
            last_value: ValueId(0),
            env: HashMap::new(),
            lowered_blocks: HashMap::new(),
        }
    }

    /// Creates a new basic block and returns its ID.
    fn new_block(&mut self) -> BlockId {
        self.blocks.insert_with_key(|id| Block {
            id,
            phi: Vec::new(),
            instr: Vec::new(),
            term: None,
            succ: Vec::new(),
            preds: Vec::new(),
        })
    }

    /// TODO
    fn new_value(&mut self) -> ValueId {
        let id = ValueId(self.inst.len());
        assert_ne!(id, self.last_value);
        self.last_value = id;
        id
    }

    /// Adds the instruction to the current block's instruction
    /// list.
    fn emit<T>(&mut self, v: T) -> ValueId
    where
        T: Into<InstKind>,
    {
        let id = self.new_value();
        self.inst.push(Inst {
            dst: id,
            kind: v.into(),
        });
        let block = &mut self.blocks[self.current_block];
        block.instr.push(id);
        id
    }

    fn join(&mut self, value: ValueId) {
        let block = &mut self.blocks[self.current_block];
        block.phi.push(value);
    }

    /// Adds the terminator to the current block.
    fn terminate(&mut self, term: Terminator) {
        let old_next = mem::take(&mut self.blocks[self.current_block].succ);
        for old_next in old_next {
            let prev = &mut self.blocks[old_next].preds;
            if let Some(pos) = prev.iter().position(|&b| b == self.current_block) {
                prev.remove(pos);
            }
        }
        let new_next = match &term {
            Terminator::Return(_) | Terminator::Panic => Vec::new(),
            Terminator::Jump(id) => {
                vec![*id]
            }
            Terminator::Branch(v) => {
                vec![v.true_block, v.false_block]
            }
        };
        for next in &new_next {
            self.blocks[*next].preds.push(self.current_block);
        }

        let block = &mut self.blocks[self.current_block];
        block.succ = new_next;
        block.term = Some(term);
    }

    /// Sets the current block.
    fn set_current(&mut self, block: BlockId) {
        self.current_block = block;
    }

    /// Binds a value to an identifier in the current scope.
    ///
    /// It returns `val`.
    fn bind(&mut self, ident: IdentId, val: ValueId) -> ValueId {
        self.env.insert(ident, val);
        val
    }

    /// Retrieves a value given its identifier.
    fn lookup(&self, ident: IdentId) -> Option<ValueId> {
        self.env.get(&ident).copied()
    }
}

impl<'hir> FuncLowerCtx<'hir> {
    fn lower_action(mut self, def: &'hir ActionDef) -> Func {
        let block = self.new_block();
        self.set_current(block);

        // Handle action arguments
        for &id in &def.args {
            let arg = &self.hir.action_args[id];
            let value = self.new_value();
            self.params.push(value);
            self.bind(arg.ident, value);
        }

        // Lower the action body
        let _ = self.lower_block(def.block); // TODO

        Func {
            ident: def.ident,
            params: self.params,
            return_type: None,
            entry: BlockId::default(),
            blocks: self.blocks,
            instr: self.inst,
        }
    }

    fn lower_func(mut self, def: &'hir FuncDef) -> Func {
        let block = self.new_block();
        self.set_current(block);

        for &id in &def.args {
            let arg = &self.hir.func_args[id];
            let value = self.new_value();
            self.params.push(value);
            self.bind(arg.ident, value);
        }

        // TODO(eric): After HIR, normalize the function body
        // such that we always end with a return statement.
        let block = &self.hir.blocks[def.block];
        let last = &self.hir.stmts[block.stmts[block.stmts.len() - 1]];
        if !matches!(last.kind, StmtKind::Return(_)) {
            panic!("last statement in function must be `return`");
        }

        let _ = self.lower_block(def.block); // TODO

        Func {
            ident: def.ident,
            params: self.params,
            return_type: Some(()),
            entry: BlockId::default(),
            blocks: self.blocks,
            instr: self.inst,
        }
    }

    fn lower_expr(&mut self, id: ExprId) -> ValueId {
        let expr = &self.hir.exprs[id];
        match &expr.kind {
            ExprKind::Int(v) => self.emit(Const {
                val: ConstValue::Int(*v),
            }),
            _ => todo!(),
        }
    }

    /// Lowers a HIR block.
    fn lower_block(&mut self, id: hir::BlockId) -> ValueId {
        // TODO(eric): use `self.lowered_blocks`.

        let init = self.emit(Const {
            val: ConstValue::Unit,
        });
        self.hir.blocks[id]
            .stmts
            .iter()
            .fold(init, |_, &id| self.lower_stmt(id))
    }

    fn lower_stmt(&mut self, id: StmtId) -> ValueId {
        let stmt = &self.hir.stmts[id];
        match &stmt.kind {
            StmtKind::Let(v) => {
                let val = self.lower_expr(v.expr);
                self.bind(v.ident, val)
            }
            StmtKind::Check(v) => self.lower_check_stmt(v),
            StmtKind::Match(v) => self.lower_match_stmt(v),
            StmtKind::If(v) => self.lower_if_stmt(v),
            StmtKind::Finish(v) => self.lower_block(*v),
            StmtKind::Map(v) => self.lower_map_stmt(v),
            StmtKind::Return(v) => self.lower_return_stmt(v),
            StmtKind::ActionCall(_) => {
                todo!()
            }
            StmtKind::Publish(_) => {
                todo!()
            }
            StmtKind::Create(_) => {
                todo!()
            }
            StmtKind::Update(_) => {
                todo!()
            }
            StmtKind::Delete(_) => {
                todo!()
            }
            StmtKind::Emit(_) => {
                todo!()
            }
            StmtKind::FunctionCall(_) => {
                todo!()
            }
            StmtKind::DebugAssert(_) => {
                todo!()
            }
        }
    }

    /// Lowers a [`CheckStmt`].
    fn lower_check_stmt(&mut self, stmt: &CheckStmt) -> ValueId {
        // Branch on `cond`.
        let cond = self.lower_expr(stmt.expr);

        // If `cond` is true, continue to `true_block`.
        // Otherwise, continue to `false_block`.
        let true_block = self.new_block();
        let false_block = self.new_block();
        self.terminate(Terminator::Branch(Branch {
            cond,
            true_block,
            false_block,
        }));

        // `false_block` immediately panics.
        self.set_current(false_block);
        self.terminate(Terminator::Panic);

        self.set_current(true_block);
        self.emit(Const {
            val: ConstValue::Unit,
        })
    }

    /// Lowers a [`MatchStmt`].
    fn lower_match_stmt(&mut self, _stmt: &MatchStmt) -> ValueId {
        unreachable!("match statements should have been normalized into if/else")
    }

    /// Lowers an [`IfStmt`].
    fn lower_if_stmt(&mut self, stmt: &IfStmt) -> ValueId {
        debug_assert!(!stmt.branches.is_empty());

        let join_block = self.new_block();
        let mut incoming = Vec::new();

        // NB: `stmt.branches` and `branch_blocks` have the same
        // length, so this skips the last element in
        // `stmt.branches`, which is what we want to do.
        for branch in &stmt.branches {
            // The condition we're branching on.
            // Ie, `if cond_val` or `else if cond_val`.
            let cond = self.lower_expr(branch.expr);

            // If `cond` is true, branch to `true_block`.
            // Otherwise, branch to `false_block`.
            let true_block = self.new_block();
            let false_block = self.new_block();
            self.terminate(Terminator::Branch(Branch {
                cond,
                true_block,
                false_block,
            }));

            self.set_current(true_block);
            let true_val = self.lower_block(branch.block);
            self.terminate(Terminator::Jump(join_block));
            incoming.push((true_block, true_val));

            self.set_current(false_block);
        }

        if let Some(id) = stmt.else_block {
            // NB: `self.current_block` == `false_block` from the
            // last iteration of the above loop.
            let else_val = self.lower_block(id);
            incoming.push((self.current_block, else_val));
        } else {
            let val = self.emit(Const {
                val: ConstValue::Unit,
            });
            incoming.push((self.current_block, val));
        }
        self.terminate(Terminator::Jump(join_block));

        self.set_current(join_block);
        let dst = self.emit(Phi { incoming });
        self.join(dst);
        dst
    }

    /// Lowers a [`MapStmt`].
    fn lower_map_stmt(&mut self, _stmt: &MapStmt) -> ValueId {
        todo!()
    }

    /// Lowers a [`ReturnStmt`].
    fn lower_return_stmt(&mut self, stmt: &ReturnStmt) -> ValueId {
        let val = self.lower_expr(stmt.expr);
        self.terminate(Terminator::Return(val));
        val
    }

    fn lower_action_call(&mut self, _call: &ActionCall) -> ValueId {
        todo!()
    }
}

/*
impl LowerCtx<'_> {
    /// Lowers an action definition.
    fn lower_action(&mut self, def: &ActionDef) {
        self.push_scope();

        let ctx = FuncCtx {
            id: def.id,
            ident: def.ident,
            params: def.params.iter().map(|p| p.ident).collect(),
            return_type: def.return_type,
        };
        let f = ctx.lower_action();

        self.pop_scope();
    }

    /// Lowers a fact literal.
    fn lower_fact_literal(
        &mut self,
        fact: &FactLiteral,
    ) -> (FactId, Vec<(IdentId, ValueId)>, Vec<(IdentId, ValueId)>) {
        // Resolve fact name to FactId
        let fact_id = self.resolve_fact_id(fact.ident);

        // Lower key fields
        let mut key_filters = Vec::new();
        for (ident, field) in &fact.keys {
            match field {
                FactField::Expr(expr_id) => {
                    let value = self.lower_expr(*expr_id);
                    key_filters.push((*ident, value));
                }
                FactField::Bind => {
                    // Allocate a fresh ValueId for the binding
                    let value = self.new_value();
                    self.bind(*ident, value);
                    key_filters.push((*ident, value));
                }
            }
        }

        // Lower value fields
        let mut val_filters = Vec::new();
        for (ident, field) in &fact.vals {
            match field {
                FactField::Expr(expr_id) => {
                    let value = self.lower_expr(*expr_id);
                    val_filters.push((*ident, value));
                }
                FactField::Bind => {
                    // Allocate a fresh ValueId for the binding
                    let value = self.new_value();
                    self.bind(*ident, value);
                    val_filters.push((*ident, value));
                }
            }
        }

        (fact_id, key_filters, val_filters)
    }

    fn resolve_fact_id(&self, ident: IdentId) -> FactId {
        // TODO: Implement proper fact resolution
        // For now, we'll need to search through the facts collection
        // This should be optimized with a name-to-id mapping
        for (fact_id, fact_def) in &self.hir.facts {
            if fact_def.ident == ident {
                return *fact_id;
            }
        }
        panic!("Fact not found: {:?}", ident);
    }

    fn track_type(&mut self, value_id: ValueId, type_id: VTypeId) {
        self.value_types.insert(value_id, type_id);
    }

    fn get_expr_type(&self, expr_id: ExprId) -> VTypeId {
        // Assume type information is already available
        self.expr_types.get(expr_id).copied().unwrap_or_else(|| {
            // Fallback to a default type if not available
            // This should be improved by proper type inference
            for (type_id, vtype) in &self.hir.types {
                if matches!(vtype.kind, VTypeKind::Int) {
                    return *type_id;
                }
            }
            // Create a default Int type if none exists
            self.hir.types.insert_with_key(|id| VType {
                id,
                span: self.hir.exprs[expr_id].span,
                kind: VTypeKind::Int,
            })
        })
    }

    fn resolve_field_id(&self, base_expr_id: ExprId, field_ident_id: IdentId) -> FieldId {
        // Get the type of the base expression
        let base_type_id = self.get_expr_type(base_expr_id);
        let base_type = &self.hir.types[base_type_id];

        match &base_type.kind {
            VTypeKind::Struct(struct_ident_id) => {
                // Find the struct definition
                let struct_id = self.find_struct_by_ident(*struct_ident_id);
                let struct_def = &self.hir.structs[struct_id];

                // Find the field in the struct
                for field_id in &struct_def.items {
                    let field_def = &self.hir.struct_fields[*field_id];
                    match &field_def.kind {
                        StructFieldKind::Field { ident, .. } => {
                            if *ident == field_ident_id {
                                return FieldId::Struct(*field_id);
                            }
                        }
                        StructFieldKind::StructRef(struct_ref) => {
                            // Handle struct field insertion - recursively look up fields in the referenced struct
                            let referenced_struct_id = self.find_struct_by_ident(struct_ref.ident);
                            let referenced_struct_def = &self.hir.structs[referenced_struct_id];

                            // Recursively search for the field in the referenced struct
                            for field_id in &referenced_struct_def.items {
                                let field_def = &self.hir.struct_fields[*field_id];
                                match &field_def.kind {
                                    StructFieldKind::Field { ident, .. } => {
                                        if *ident == field_ident_id {
                                            return FieldId::Struct(*field_id);
                                        }
                                    }
                                    StructFieldKind::StructRef(_) => {
                                        // TODO: Handle nested struct field insertion
                                        // This would require deeper recursion
                                    }
                                }
                            }

                            // Field not found in referenced struct
                            panic!(
                                "Field {:?} not found in referenced struct {:?}",
                                field_ident_id, struct_ref.ident
                            );
                        }
                    }
                }

                // Field not found in struct
                panic!(
                    "Field {:?} not found in struct {:?}",
                    field_ident_id, struct_ident_id
                );
            }
            VTypeKind::Enum(enum_ident_id) => {
                // TODO: Handle enum field access
                // The HIR doesn't have detailed enum variant/field information
                // For now, just panic with a helpful message
                panic!(
                    "Enum field access not yet implemented for enum {:?}",
                    enum_ident_id
                );
            }
            _ => {
                panic!("Cannot access field on type {:?}", base_type.kind);
            }
        }
    }

    fn find_struct_by_ident(&self, struct_ident_id: IdentId) -> StructId {
        // Find the struct definition by its identifier
        for (struct_id, struct_def) in &self.hir.structs {
            if struct_def.ident == struct_ident_id {
                return struct_id;
            }
        }
        panic!("Struct not found for identifier {:?}", struct_ident_id);
    }

    fn find_enum_by_ident(&self, enum_ident_id: IdentId) -> EnumId {
        // Find the enum definition by its identifier
        for (enum_id, enum_def) in &self.hir.enums {
            if enum_def.ident == enum_ident_id {
                return enum_id;
            }
        }
        panic!("Enum not found for identifier {:?}", enum_ident_id);
    }

    fn resolve_effect_id(&self, effect_expr_id: ExprId) -> EffectId {
        // TODO: Implement effect resolution
        // This should look up the effect definition based on the expression
        // For now, return a placeholder
        for (effect_id, _) in &self.hir.effects {
            return *effect_id;
        }
        panic!("No effects found");
    }

    fn lower_effect_fields(&mut self, effect_expr_id: ExprId) -> Vec<(IdentId, ValueId)> {
        // TODO: Implement effect field lowering
        // This should extract field values from the effect expression
        // For now, return empty vector
        Vec::new()
    }

    fn resolve_command_id(&self, cmd_expr_id: ExprId) -> CmdId {
        // TODO: Implement command resolution
        // This should look up the command definition based on the expression
        // For now, return a placeholder
        for (cmd_id, _) in &self.hir.cmds {
            return *cmd_id;
        }
        panic!("No commands found");
    }

    fn lower_command_fields(&mut self, cmd_expr_id: ExprId) -> Vec<(IdentId, ValueId)> {
        // TODO: Implement command field lowering
        // This should extract field values from the command expression
        // For now, return empty vector
        Vec::new()
    }

    fn lower_expr(&mut self, expr_id: ExprId) -> ValueId {
        let expr = &self.hir.exprs[expr_id];
        let result = match &expr.kind {
            ExprKind::Int(val) => {
                let dst = self.new_value();
                let inst = Inst::Const(Const {
                    dst,
                    val: ConstValue::Int(*val),
                });
                self.emit(inst);
                dst
            }
            ExprKind::String(text) => {
                let dst = self.new_value();
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Const(ConstValue::Text(text.clone())),
                    },
                }));
                dst
            }
            ExprKind::Bool(val) => {
                let dst = self.new_value();
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Const(ConstValue::Bool(*val)),
                    },
                }));
                dst
            }
            ExprKind::Optional(opt_expr) => {
                match opt_expr {
                    Some(expr_id) => {
                        let inner_val = self.lower_expr(*expr_id);
                        // TODO: Create Some wrapper
                        inner_val
                    }
                    None => {
                        let dst = self.new_value();
                        self.emit(Inst::Const(Const {
                            dst,
                            val: Value {
                                id: dst,
                                kind: ValueKind::Const(ConstValue::None),
                            },
                        }));
                        dst
                    }
                }
            }
            ExprKind::Identifier(ident_id) => {
                if let Some(val) = self.lookup(*ident_id) {
                    val
                } else {
                    // This is a parameter or global variable
                    let dst = self.new_value();
                    let ident = &self.hir.idents[*ident_id];
                    self.emit(Inst::Load(Load {
                        dst,
                        name: SymbolId::from(ident.ident.clone()),
                    }));
                    dst
                }
            }
            ExprKind::Dot(base_expr, field_ident) => {
                let base_val = self.lower_expr(*base_expr);
                let dst = self.new_value();

                // Resolve the field ID by looking up the struct definition
                let field_id = self.resolve_field_id(*base_expr, *field_ident);

                self.emit(Inst::FieldAccess(FieldAccess {
                    dst,
                    base: base_val,
                    field: field_id,
                }));
                dst
            }
            ExprKind::Add(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Add,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::Sub(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Sub,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::And(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::And,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::Or(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Or,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::Equal(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Eq,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::NotEqual(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Eq,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                // Negate the result
                let not_dst = self.new_value();
                self.emit(Inst::UnaryOp(UnaryOp {
                    dst: not_dst,
                    kind: UnaryOpKind::Not,
                    src: dst,
                }));
                not_dst
            }
            ExprKind::GreaterThan(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Gt,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::LessThan(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::Lt,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::GreaterThanOrEqual(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::GtEq,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::LessThanOrEqual(lhs, rhs) => {
                let lhs_val = self.lower_expr(*lhs);
                let rhs_val = self.lower_expr(*rhs);
                let dst = self.new_value();
                self.emit(Inst::BinOp(BinOp {
                    dst,
                    kind: BinOpKind::LtEq,
                    lhs: lhs_val,
                    rhs: rhs_val,
                }));
                dst
            }
            ExprKind::Negative(expr) => {
                let src_val = self.lower_expr(*expr);
                let dst = self.new_value();
                self.emit(Inst::UnaryOp(UnaryOp {
                    dst,
                    kind: UnaryOpKind::Neg,
                    src: src_val,
                }));
                dst
            }
            ExprKind::Not(expr) => {
                let src_val = self.lower_expr(*expr);
                let dst = self.new_value();
                self.emit(Inst::UnaryOp(UnaryOp {
                    dst,
                    kind: UnaryOpKind::Not,
                    src: src_val,
                }));
                dst
            }
            ExprKind::Unwrap(expr) => {
                let src_val = self.lower_expr(*expr);
                // TODO: Implement unwrap logic - this should check if the optional is Some
                // and extract the value, or panic if it's None
                src_val
            }
            ExprKind::CheckUnwrap(expr) => {
                let src_val = self.lower_expr(*expr);
                // TODO: Implement check_unwrap logic - similar to unwrap but with check failure
                src_val
            }
            ExprKind::Intrinsic(intrin) => match intrin {
                Intrinsic::Query(fact_literal) => {
                    let (fact_id, key_filters, val_filters) = self.lower_fact_literal(fact_literal);
                    let dst = self.new_value();
                    self.emit(Inst::Query(Query {
                        dst,
                        fact_id,
                        key_filters,
                        val_filters,
                    }));
                    dst
                }
                Intrinsic::FactCount(count_type, limit, fact_literal) => {
                    let (fact_id, key_filters, val_filters) = self.lower_fact_literal(fact_literal);
                    let dst = self.new_value();
                    self.emit(Inst::FactCount(FactCount {
                        dst,
                        fact_id,
                        key_filters,
                        count_type: match count_type {
                            hir::FactCountType::UpTo =>FactCountType::UpTo,
                            hir::FactCountType::AtLeast =>FactCountType::AtLeast,
                            hir::FactCountType::AtMost =>FactCountType::AtMost,
                            hir::FactCountType::Exactly =>FactCountType::Exactly,
                        },
                        limit: *limit,
                    }));
                    dst
                }
                Intrinsic::Serialize(expr) => {
                    let src_val = self.lower_expr(*expr);
                    let dst = self.new_value();
                    self.emit(Inst::Serialize(crate::mir::ssa::SerializeValue {
                        dst,
                        src: src_val,
                    }));
                    dst
                }
                Intrinsic::Deserialize(expr) => {
                    let src_val = self.lower_expr(*expr);
                    let dst = self.new_value();
                    self.emit(Inst::Deserialize(crate::mir::ssa::DeserializeValue {
                        dst,
                        src: src_val,
                    }));
                    dst
                }
            },
            ExprKind::Match(_expr) => {
                // TODO
            }
            ExprKind::Ternary(v) => self.lower_ternary_expr(v),
            ExprKind::NamedStruct(named_struct) => {
                // Lower all field values
                let mut field_values = Vec::new();
                for (field_ident, field_expr) in &named_struct.fields {
                    let field_val = self.lower_expr(*field_expr);
                    field_values.push((*field_ident, field_val));
                }

                let dst = self.new_value();
                // TODO: Implement struct creation instruction
                // For now, just return a placeholder value
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Const(ConstValue::Int(0)),
                    },
                }));
                dst
            }
            ExprKind::FunctionCall(func_call) => {
                // Lower all arguments
                let mut args = Vec::new();
                for arg_expr_id in &func_call.args {
                    let arg_val = self.lower_expr(*arg_expr_id);
                    args.push(arg_val);
                }

                let dst = self.new_value();
                // TODO: Resolve function_call.ident to function value
                let func_val = self.new_value(); // Placeholder
                self.emit(Inst::Call(Call {
                    dst,
                    func: func_val,
                    args,
                }));
                dst
            }
            ExprKind::ForeignFunctionCall(foreign_call) => {
                // Lower all arguments
                let mut args = Vec::new();
                for arg_expr_id in &foreign_call.args {
                    let arg_val = self.lower_expr(*arg_expr_id);
                    args.push(arg_val);
                }

                let dst = self.new_value();
                // TODO: Implement foreign function call
                // For now, just return a placeholder value
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Const(ConstValue::Int(0)),
                    },
                }));
                dst
            }
            ExprKind::EnumReference(enum_ref) => {
                let dst = self.new_value();
                // TODO: Implement enum reference
                // For now, just return a placeholder value
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Const(ConstValue::Int(0)),
                    },
                }));
                dst
            }
            ExprKind::Substruct(base_expr, struct_ident) => {
                // Lower the base expression
                let base_val = self.lower_expr(*base_expr);
                let dst = self.new_value();

                // TODO: Implement substruct operation
                // This should create a new struct with the specified fields from the base
                // For now, just return the base value
                self.emit(Inst::Const(Const {
                    dst,
                    val: Value {
                        id: dst,
                        kind: ValueKind::Value(base_val),
                    },
                }));
                dst
            }
            ExprKind::Load(ident) => {
                // Load a variable from the environment
                let dst = self.new_value();
                self.emit(Inst::Load(Load {
                    dst,
                    name: *ident, // TODO: Convert IdentId to SymbolId
                }));
                dst
            }
            // TODO: Implement remaining expression kinds
            _ => {
                panic!("Unimplemented expression kind: {:?}", expr.kind);
            }
        };

        // Track the type of the result
        let type_id = self.get_expr_type(expr_id);
        self.track_type(result, type_id);

        result
    }

    fn lower_stmt(&mut self, stmt_id: StmtId) {
        let stmt = &self.hir.stmts[stmt_id];
        match &stmt.kind {
            StmtKind::Let(let_stmt) => {
                let expr_val = self.lower_expr(let_stmt.expr);
                self.bind(let_stmt.ident, expr_val);
            }
            StmtKind::Check(check_stmt) => {
                let cond_val = self.lower_expr(check_stmt.expr);
                let true_block = self.new_block();
                let false_block = self.panic_block;

                self.terminate(Terminator::CondJump(CondJump {
                    cond: cond_val,
                    true_block,
                    false_block,
                }));

                self.set_current(true_block);
            }
            StmtKind::Match(match_stmt) => {
                // Lower match statement to if/else chain
                self.lower_match_stmt(match_stmt);
            }
            StmtKind::Return(return_stmt) => {
                let expr_val = self.lower_expr(return_stmt.expr);
                self.terminate(Terminator::Return(expr_val));
            }
            StmtKind::ActionCall(action_call) => {
                // Lower all arguments
                let mut args = Vec::new();
                for arg_expr in &action_call.args {
                    let arg_val = self.lower_expr(*arg_expr);
                    args.push(arg_val);
                }

                let dst = self.new_value();
                // TODO: Resolve action_call.ident to function value
                let func_val = self.new_value(); // Placeholder
                self.emit(Inst::Call(Call {
                    dst,
                    func: func_val,
                    args,
                }));
            }
            StmtKind::Create(create_stmt) => {
                let (fact_id, keys, values) = self.lower_fact_literal(&create_stmt.fact);
                let dst = self.new_value();
                self.emit(Inst::Create(Create {
                    dst,
                    fact_id,
                    keys,
                    values,
                }));
            }
            StmtKind::Update(update_stmt) => {
                let (fact_id, keys, old_values) = self.lower_fact_literal(&update_stmt.fact);

                // Lower the "to" values
                let mut new_values = Vec::new();
                for (ident, field) in &update_stmt.to {
                    match field {
                        FactField::Expr(expr_id) => {
                            let value = self.lower_expr(*expr_id);
                            new_values.push((*ident, value));
                        }
                        FactField::Bind => {
                            // This should be an error in the policy language
                            panic!("Bind patterns not allowed in update 'to' clause");
                        }
                    }
                }

                let dst = self.new_value();
                self.emit(Inst::Update(Update {
                    dst,
                    fact_id,
                    keys,
                    old_values,
                    new_values,
                }));
            }
            StmtKind::Delete(delete_stmt) => {
                let (fact_id, key_filters, val_filters) =
                    self.lower_fact_literal(&delete_stmt.fact);
                let dst = self.new_value();
                self.emit(Inst::Delete(Delete {
                    dst,
                    fact_id,
                    key_filters,
                    val_filters,
                }));
            }
            StmtKind::Emit(emit_stmt) => {
                // Resolve the effect and lower its fields
                let effect_id = self.resolve_effect_id(emit_stmt.expr);
                let field_values = self.lower_effect_fields(emit_stmt.expr);

                let dst = self.new_value();
                self.emit(Inst::Emit(Emit {
                    dst,
                    effect_id,
                    fields: field_values,
                }));
            }
            StmtKind::Publish(publish_stmt) => {
                // Resolve the command and lower its fields
                let cmd_id = self.resolve_command_id(publish_stmt.exor);
                let field_values = self.lower_command_fields(publish_stmt.exor);

                let dst = self.new_value();
                self.emit(Inst::Publish(Publish {
                    dst,
                    cmd_id,
                    fields: field_values,
                }));
            }
            StmtKind::If(if_stmt) => {
                // Lower if statement to conditional blocks
                self.lower_if_stmt(if_stmt);
            }
            StmtKind::Map(map_stmt) => {
                // Lower map statement to iteration
                self.lower_map_stmt(map_stmt);
            }
            StmtKind::Let(let_stmt) => {
                // Lower the expression and bind it to the identifier
                let expr_val = self.lower_expr(let_stmt.expr);
                self.bind(let_stmt.ident, expr_val);
            }
            StmtKind::Check(check_stmt) => {
                // Lower the check expression
                let check_val = self.lower_expr(check_stmt.expr);
                // TODO: Implement check statement - this might be an assertion
                // For now, just evaluate the expression
            }
            StmtKind::Return(return_stmt) => {
                // Lower the return expression
                let return_val = self.lower_expr(return_stmt.expr);
                self.terminate(Terminator::Return(return_val));
            }
            StmtKind::ActionCall(action_call) => {
                // Lower all arguments
                let mut args = Vec::new();
                for arg_expr_id in &action_call.args {
                    let arg_val = self.lower_expr(*arg_expr_id);
                    args.push(arg_val);
                }

                let dst = self.new_value();
                // TODO: Resolve action_call.ident to action value
                let action_val = self.new_value(); // Placeholder
                self.emit(Inst::Call(Call {
                    dst,
                    func: action_val,
                    args,
                }));
            }
            StmtKind::FunctionCall(func_call) => {
                // Lower all arguments
                let mut args = Vec::new();
                for arg_expr_id in &func_call.args {
                    let arg_val = self.lower_expr(*arg_expr_id);
                    args.push(arg_val);
                }

                let dst = self.new_value();
                // TODO: Resolve func_call.ident to function value
                let func_val = self.new_value(); // Placeholder
                self.emit(Inst::Call(Call {
                    dst,
                    func: func_val,
                    args,
                }));
            }
            StmtKind::DebugAssert(debug_assert) => {
                // Lower the debug assertion expression
                let assert_val = self.lower_expr(debug_assert.expr);
                // TODO: Implement debug assertion
                // For now, just evaluate the expression
            }
            // TODO: Implement remaining statement kinds
            _ => {
                panic!("Unimplemented statement kind: {:?}", stmt.kind);
            }
        }
    }

    fn lower_function(&mut self, def: &FuncDef) {
        self.push_scope();

        let func_id = def.id;
        let block = self.new_block();
        self.set_current(block);

        // Handle function arguments
        for arg_id in &def.args {
            let arg = &self.hir.func_args[*arg_id];
            let value = self.new_value();
            self.bind(arg.ident, value);
        }

        // Lower the function body
        let block = self.hir.blocks.get(def.block).unwrap();
        for stmt_id in &block.stmts {
            self.lower_stmt(*stmt_id);
        }

        // FuncDefs MUST have explicit returns
        if self.blocks[self.current_block].term.is_none() {
            panic!("Function {:?} does not have a return statement", def.id);
        }

        self.pop_scope();
    }

    fn lower_finish_function(&mut self, def: &FinishFuncDef) {
        self.push_scope();

        let func_id = def.id;
        let block = self.new_block();
        self.set_current(block);

        // Handle function arguments
        for arg_id in &def.args {
            let arg = &self.hir.finish_func_args[*arg_id];
            let value = self.new_value();
            self.bind(arg.ident, value);
        }

        // Lower the function body
        let block = self.hir.blocks.get(def.block).unwrap();
        for stmt_id in &block.stmts {
            self.lower_stmt(*stmt_id);
        }

        // FinishFuncDefs don't return values, so no return terminator needed

        self.pop_scope();
    }

    pub(crate) fn lower_all(&mut self) {
        // Lower all actions
        for (_, action_def) in &self.hir.actions {
            self.lower_action(action_def);
        }

        // Lower all functions
        for (_, func_def) in &self.hir.funcs {
            self.lower_function(func_def);
        }

        // Lower all finish functions
        for (_, finish_func_def) in &self.hir.finish_funcs {
            self.lower_finish_function(finish_func_def);
        }

        // TODO: Lower other top-level items (commands, effects, etc.)
    }

    fn lower_ternary_expr(&mut self, expr: &Ternary) -> ValueId {
        // Lower the condition
        let cond_val = self.lower_expr(expr.cond);

        // Create blocks for then, else, and merge
        let then_block = self.new_block();
        let else_block = self.new_block();
        let merge_block = self.new_block();

        // Create conditional jump
        self.terminate(Terminator::CondJump(CondJump {
            cond: cond_val,
            true_block: then_block,
            false_block: else_block,
        }));

        // Lower then expression
        self.set_current(then_block);
        let then_val = self.lower_expr(expr.true_expr);
        self.terminate(Terminator::Jump(merge_block));

        // Lower else expression
        self.set_current(else_block);
        let else_val = self.lower_expr(expr.false_expr);
        self.terminate(Terminator::Jump(merge_block));

        // Create phi node in merge block
        self.set_current(merge_block);
        let phi_dst = self.new_value();

        // Create phi node to merge values from both paths
        self.emit(Inst::Phi(crate::mir::ssa::Phi {
            dst: phi_dst,
            args: vec![(then_block, then_val), (else_block, else_val)],
        }));

        phi_dst
    }

    fn lower_match_stmt(&mut self, match_stmt: &MatchStmt) {
        // Lower the scrutinee expression
        let scrutinee_val = self.lower_expr(match_stmt.expr);

        // Create blocks for each arm and a merge block
        let mut arm_blocks = Vec::new();
        for _ in &match_stmt.arms {
            arm_blocks.push(self.new_block());
        }
        let merge_block = self.new_block();

        // Create conditional jumps for each arm (except the last one)
        for (i, arm) in match_stmt.arms.iter().enumerate() {
            if i < match_stmt.arms.len() - 1 {
                // Create condition for this arm
                let cond_val = match &arm.pattern {
                    MatchPattern::Default => {
                        // Default arm - always true
                        let dst = self.new_value();
                        self.emit(Inst::Const(Const {
                            dst,
                            val: Value {
                                id: dst,
                                kind: ValueKind::Const(ConstValue::Bool(true)),
                            },
                        }));
                        dst
                    }
                    MatchPattern::Values(values) => {
                        // Compare scrutinee with each value
                        let mut cond_val = None;
                        for value_expr_id in values {
                            let value_val = self.lower_expr(*value_expr_id);
                            let eq_val = self.new_value();
                            self.emit(Inst::BinOp(BinOp {
                                dst: eq_val,
                                kind: BinOpKind::Eq,
                                lhs: scrutinee_val,
                                rhs: value_val,
                            }));

                            if let Some(prev_cond) = cond_val {
                                // OR with previous conditions
                                let or_val = self.new_value();
                                self.emit(Inst::BinOp(BinOp {
                                    dst: or_val,
                                    kind: BinOpKind::Or,
                                    lhs: prev_cond,
                                    rhs: eq_val,
                                }));
                                cond_val = Some(or_val);
                            } else {
                                cond_val = Some(eq_val);
                            }
                        }
                        cond_val.unwrap()
                    }
                };

                // Create conditional jump
                let next_arm_block = arm_blocks[i + 1];
                self.terminate(Terminator::CondJump(CondJump {
                    cond: cond_val,
                    true_block: arm_blocks[i],
                    false_block: next_arm_block,
                }));
            }
        }

        // Lower each arm's block
        for (i, arm) in match_stmt.arms.iter().enumerate() {
            self.set_current(arm_blocks[i]);

            // Lower the statements in the arm's block
            let block = self.hir.blocks.get(arm.block).unwrap();
            for stmt_id in &block.stmts {
                self.lower_stmt(*stmt_id);
            }

            // Jump to merge block
            self.terminate(Terminator::Jump(merge_block));
        }

        // Set current block to merge block
        self.set_current(merge_block);
    }

    fn lower_if_stmt(&mut self, if_stmt: &IfStmt) {
        // Create blocks for each branch and merge
        let mut branch_blocks = Vec::new();
        for _ in &if_stmt.branches {
            branch_blocks.push(self.new_block());
        }
        let else_block = if_stmt.else_block.map(|_| self.new_block());
        let merge_block = self.new_block();

        // Create conditional jumps for each branch (except the last one)
        for (i, branch) in if_stmt.branches.iter().enumerate() {
            if i < if_stmt.branches.len() - 1 {
                // Create condition for this branch
                let cond_val = self.lower_expr(branch.expr);

                // Create conditional jump
                let next_branch_block = branch_blocks[i + 1];
                self.terminate(Terminator::CondJump(CondJump {
                    cond: cond_val,
                    true_block: branch_blocks[i],
                    false_block: next_branch_block,
                }));
            }
        }

        // Lower each branch's block
        for (i, branch) in if_stmt.branches.iter().enumerate() {
            self.set_current(branch_blocks[i]);

            // Lower the statements in the branch's block
            let block = self.hir.blocks.get(branch.block).unwrap();
            for stmt_id in &block.stmts {
                self.lower_stmt(*stmt_id);
            }

            // Jump to merge block
            self.terminate(Terminator::Jump(merge_block));
        }

        // Handle else block if present
        if let Some(else_block_id) = else_block {
            self.set_current(else_block_id);

            if let Some(else_block_def) = if_stmt.else_block {
                let block = self.hir.blocks.get(else_block_def).unwrap();
                for stmt_id in &block.stmts {
                    self.lower_stmt(*stmt_id);
                }
            }

            self.terminate(Terminator::Jump(merge_block));
        }

        // Set current block to merge block
        self.set_current(merge_block);
    }

    fn lower_map_stmt(&mut self, map_stmt: &MapStmt) {
        // Lower the fact literal to get the query
        let (fact_id, key_filters, val_filters) = self.lower_fact_literal(&map_stmt.fact);

        // Create blocks for map iteration
        let start_block = self.new_block();
        let body_block = self.new_block();
        let next_block = self.new_block();
        let end_block = self.new_block();

        // Start map iteration
        let map_id = self.new_value();
        self.emit(Inst::MapStart(crate::mir::ssa::MapStart {
            dst: map_id,
            fact_id,
            key_filters,
            val_filters,
        }));

        // Create conditional jump to check if we have more items
        self.terminate(Terminator::CondJump(CondJump {
            cond: map_id,
            true_block: body_block,
            false_block: end_block,
        }));

        // Map body block
        self.set_current(body_block);

        // Bind the current item to the identifier
        let item_val = self.new_value();
        self.emit(Inst::MapNext(crate::mir::ssa::MapNext {
            dst: item_val,
            map_id,
        }));
        self.bind(map_stmt.ident, item_val);

        // Lower the statements in the map body
        let block = self.hir.blocks.get(map_stmt.block).unwrap();
        for stmt_id in &block.stmts {
            self.lower_stmt(*stmt_id);
        }

        // Jump back to next block
        self.terminate(Terminator::Jump(next_block));

        // Next block - get next item
        self.set_current(next_block);
        let next_dst = self.new_value();
        self.emit(Inst::MapNext(crate::mir::ssa::MapNext {
            dst: next_dst,
            map_id,
        }));

        // Jump back to start to check if we have more items
        self.terminate(Terminator::Jump(start_block));

        // Set current block to end block
        self.set_current(end_block);
    }
}
*/
