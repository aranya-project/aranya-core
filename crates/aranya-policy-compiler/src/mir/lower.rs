use std::{collections::HashMap, mem};

use slotmap::SlotMap;

use crate::{
    hir::{self, HirView, IdentId},
    mir::{
        Mir,
        ssa::{
            BinOp, Block, BlockId, Branch, Call, Const, ConstValue, Create, Delete,
            DeserializeValue, Emit, FactCount, FactCountType, FieldAccess, FieldId, Func, FuncId,
            Inst, InstKind, Load, Phi, Publish, Query, SerializeValue, Terminator, UnaryOp, Update,
            ValueId,
        },
    },
    simplify as s,
    symtab::{ItemKind, SymbolId, SymbolsView, TypeKind},
};

// ----------------------------------------------------------------------------
// Simplified IR → MIR SSA
// ----------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct SimplLowerCtx<'s, 'cx> {
    sh: &'s s::Hir,
    hir: HirView<'cx>,
    symbols: SymbolsView<'cx>,
    /// All basic blocks.
    blocks: SlotMap<BlockId, Block>,
    /// The current basic block.
    current_block: BlockId,
    /// Instructions keyed by ValueId (flat list across blocks)
    inst: Vec<Inst>,
    last_value: ValueId,
    /// Simple local environment for identifiers during expression lowering
    env: HashMap<IdentId, ValueId>,
}

impl<'s, 'cx> SimplLowerCtx<'s, 'cx> {
    fn new(sh: &'s s::Hir, hir: HirView<'cx>, symbols: SymbolsView<'cx>) -> Self {
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
            sh,
            hir,
            symbols,
            blocks,
            current_block,
            inst: Vec::new(),
            last_value: ValueId(0),
            env: HashMap::new(),
        }
    }

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

    fn set_current(&mut self, block: BlockId) {
        self.current_block = block;
    }

    fn new_value(&mut self) -> ValueId {
        let id = ValueId(self.inst.len());
        assert_ne!(id, self.last_value);
        self.last_value = id;
        id
    }

    fn emit<T: Into<InstKind>>(&mut self, v: T) -> ValueId {
        let id = self.new_value();
        self.inst.push(Inst {
            dst: id,
            kind: v.into(),
        });
        let block = &mut self.blocks[self.current_block];
        block.instr.push(id);
        id
    }

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
            Terminator::Jump(id) => vec![*id],
            Terminator::Branch(v) => vec![v.true_block, v.false_block],
        };
        for next in &new_next {
            self.blocks[*next].preds.push(self.current_block);
        }
        let block = &mut self.blocks[self.current_block];
        block.succ = new_next;
        block.term = Some(term);
    }

    fn bind(&mut self, ident: IdentId, val: ValueId) -> ValueId {
        self.env.insert(ident, val);
        val
    }

    fn lookup(&self, ident: IdentId) -> Option<ValueId> {
        self.env.get(&ident).copied()
    }

    fn resolve_symbol(&self, ident: IdentId) -> Option<SymbolId> {
        self.symbols.table().item_resolutions.get(&ident).copied()
    }

    fn resolve_fact(&self, ident: IdentId) -> Option<hir::FactId> {
        let sym = self.resolve_symbol(ident)?;
        match self.symbols.table().get(sym)?.kind {
            crate::symtab::SymbolKind::Item(ItemKind::Fact(id)) => Some(id),
            _ => None,
        }
    }

    fn resolve_cmd(&self, ident: IdentId) -> Option<hir::CmdId> {
        let sym = self.resolve_symbol(ident)?;
        match self.symbols.table().get(sym)?.kind {
            crate::symtab::SymbolKind::Item(ItemKind::Cmd(id)) => Some(id),
            _ => None,
        }
    }

    fn resolve_effect(&self, ident: IdentId) -> Option<hir::EffectId> {
        let sym = self.resolve_symbol(ident)?;
        match self.symbols.table().get(sym)?.kind {
            crate::symtab::SymbolKind::Item(ItemKind::Effect(id)) => Some(id),
            _ => None,
        }
    }

    fn resolve_func_like(&self, ident: IdentId) -> Option<SymbolId> {
        let sym = self.resolve_symbol(ident)?;
        match self.symbols.table().get(sym)?.kind {
            crate::symtab::SymbolKind::Item(ItemKind::Func(_))
            | crate::symtab::SymbolKind::Item(ItemKind::Action(_))
            | crate::symtab::SymbolKind::Item(ItemKind::FinishFunc(_))
            | crate::symtab::SymbolKind::Item(ItemKind::FfiFunc(_)) => Some(sym),
            _ => None,
        }
    }

    fn lower_fact_literal_filters(
        &mut self,
        lit: &s::FactLiteral,
    ) -> Option<(
        hir::FactId,
        Vec<(hir::IdentId, ValueId)>,
        Vec<(hir::IdentId, ValueId)>,
    )> {
        let fact_id = self.resolve_fact(lit.ident)?;
        let mut key_filters: Vec<(hir::IdentId, ValueId)> = Vec::new();
        let mut val_filters: Vec<(hir::IdentId, ValueId)> = Vec::new();
        for f in &lit.keys {
            match &f.expr {
                s::FactField::Expr(eid) => {
                    let v = self.lower_expr(*eid);
                    key_filters.push((f.ident, v));
                }
                s::FactField::Bind => {}
            }
        }
        for f in &lit.vals {
            match &f.expr {
                s::FactField::Expr(eid) => {
                    let v = self.lower_expr(*eid);
                    val_filters.push((f.ident, v));
                }
                s::FactField::Bind => {}
            }
        }
        Some((fact_id, key_filters, val_filters))
    }

    fn resolve_struct_ident(&self, ident: hir::IdentId) -> Option<hir::StructId> {
        let sym = *self.symbols.table().type_resolutions.get(&ident)?;
        match self.symbols.table().get(sym)?.kind {
            crate::symtab::SymbolKind::Type(TypeKind::Struct(id, _)) => Some(id),
            _ => None,
        }
    }

    fn map_struct_field(
        &self,
        struct_id: hir::StructId,
        field_ident: hir::IdentId,
    ) -> Option<hir::StructFieldId> {
        fn walk(
            this: &SimplLowerCtx<'_, '_>,
            sid: hir::StructId,
            target: hir::IdentId,
        ) -> Option<hir::StructFieldId> {
            let sdef = &this.hir.hir().structs[sid];
            for &sfid in &sdef.items {
                let sf = &this.hir.hir().struct_fields[sfid];
                match &sf.kind {
                    hir::StructFieldKind::Field { ident, .. } => {
                        if *ident == target {
                            return Some(sfid);
                        }
                    }
                    hir::StructFieldKind::StructRef(sident) => {
                        if let Some(inner_sid) = this.resolve_struct_ident(*sident) {
                            if let Some(found) = walk(this, inner_sid, target) {
                                return Some(found);
                            }
                        }
                    }
                }
            }
            None
        }
        walk(self, struct_id, field_ident)
    }

    fn map_cmd_field(&self, cmd_id: hir::CmdId, field_ident: hir::IdentId) -> Option<FieldId> {
        let cdef = &self.hir.hir().cmds[cmd_id];
        for &cfid in &cdef.fields {
            let cf = &self.hir.hir().cmd_fields[cfid];
            match &cf.kind {
                hir::CmdFieldKind::Field { ident, .. } => {
                    if *ident == field_ident {
                        return Some(FieldId::Command(cfid));
                    }
                }
                hir::CmdFieldKind::StructRef(sident) => {
                    if let Some(sid) = self.resolve_struct_ident(*sident) {
                        if let Some(sfid) = self.map_struct_field(sid, field_ident) {
                            return Some(FieldId::Struct(sfid));
                        }
                    }
                }
            }
        }
        None
    }

    fn map_effect_field(
        &self,
        effect_id: hir::EffectId,
        field_ident: hir::IdentId,
    ) -> Option<FieldId> {
        let edef = &self.hir.hir().effects[effect_id];
        for &efid in &edef.items {
            let ef = &self.hir.hir().effect_fields[efid];
            match &ef.kind {
                hir::EffectFieldKind::Field { ident, .. } => {
                    if *ident == field_ident {
                        return Some(FieldId::Effect(efid));
                    }
                }
                hir::EffectFieldKind::StructRef(sident) => {
                    if let Some(sid) = self.resolve_struct_ident(*sident) {
                        if let Some(sfid) = self.map_struct_field(sid, field_ident) {
                            return Some(FieldId::Struct(sfid));
                        }
                    }
                }
            }
        }
        None
    }

    fn lower_expr(&mut self, id: s::ExprId) -> ValueId {
        let expr = &self.sh.exprs[id];
        match &expr.kind {
            s::ExprKind::LitInt(v) => self.emit(Const {
                val: ConstValue::Int(*v),
            }),
            s::ExprKind::LitBool(b) => self.emit(Const {
                val: ConstValue::Bool(*b),
            }),
            s::ExprKind::LitString(_t) => self.emit(Const {
                val: ConstValue::Int(0),
            }),
            s::ExprKind::Ident(ident) => match self.lookup(*ident) {
                Some(v) => v,
                None => match self.resolve_symbol(*ident) {
                    Some(sym) => self.emit(Load { name: sym }),
                    None => self.emit(Const {
                        val: ConstValue::Unit,
                    }),
                },
            },
            s::ExprKind::Unary(op, e) => {
                let src = self.lower_expr(*e);
                match op {
                    hir::UnaryOp::Not => self.emit(UnaryOp::Not(src)),
                    hir::UnaryOp::Neg => self.emit(UnaryOp::Neg(src)),
                    _ => src,
                }
            }
            s::ExprKind::Intrinsic(i) => match i {
                s::Intrinsic::Serialize(e) => {
                    let v = self.lower_expr(*e);
                    self.emit(SerializeValue { src: v })
                }
                s::Intrinsic::Deserialize(e) => {
                    let v = self.lower_expr(*e);
                    self.emit(DeserializeValue { src: v })
                }
                s::Intrinsic::Query(lit) => {
                    if let Some((fact_id, key_filters, val_filters)) =
                        self.lower_fact_literal_filters(lit)
                    {
                        self.emit(Query {
                            fact_id,
                            key_filters,
                            val_filters,
                        })
                    } else {
                        self.emit(Const {
                            val: ConstValue::Unit,
                        })
                    }
                }
                s::Intrinsic::FactCount(kind, limit, lit) => {
                    if let Some((fact_id, key_filters, _val_filters)) =
                        self.lower_fact_literal_filters(lit)
                    {
                        let count_type = match kind {
                            hir::FactCountType::UpTo => FactCountType::UpTo,
                            hir::FactCountType::AtLeast => FactCountType::AtLeast,
                            hir::FactCountType::AtMost => FactCountType::AtMost,
                            hir::FactCountType::Exactly => FactCountType::Exactly,
                        };
                        self.emit(FactCount {
                            fact_id,
                            key_filters,
                            count_type,
                            limit: *limit,
                        })
                    } else {
                        self.emit(Const {
                            val: ConstValue::Unit,
                        })
                    }
                }
                s::Intrinsic::Todo => self.emit(Const {
                    val: ConstValue::Unit,
                }),
            },
            s::ExprKind::FunctionCall(call) => {
                if let Some(sym) = self.resolve_func_like(call.ident) {
                    let func_val = self.emit(Load { name: sym });
                    let args = call.args.iter().map(|&a| self.lower_expr(a)).collect();
                    self.emit(Call {
                        func: func_val,
                        args,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::ActionCall(call) => {
                if let Some(sym) = self.resolve_func_like(call.ident) {
                    let func_val = self.emit(Load { name: sym });
                    let args = call.args.iter().map(|&a| self.lower_expr(a)).collect();
                    self.emit(Call {
                        func: func_val,
                        args,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::ForeignFunctionCall(call) => {
                if let Some(sym) = self.resolve_func_like(call.ident) {
                    let func_val = self.emit(Load { name: sym });
                    let args = call.args.iter().map(|&a| self.lower_expr(a)).collect();
                    self.emit(Call {
                        func: func_val,
                        args,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Create(c) => {
                if let Some((fact_id, keys, vals)) = self.lower_fact_literal_filters(&c.fact) {
                    self.emit(Create {
                        fact_id,
                        keys,
                        values: vals,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Publish(p) => {
                if let Some(cmd_id) = self.resolve_cmd(p.value.ident) {
                    let mut fields = Vec::with_capacity(p.value.fields.len());
                    for f in &p.value.fields {
                        let v = self.lower_expr(f.expr);
                        if let Some(res) = &f.resolved {
                            let fid = match res {
                                s::ResolvedField::Cmd(id) => FieldId::Command(*id),
                                s::ResolvedField::Effect(id) => FieldId::Effect(*id),
                                s::ResolvedField::Struct(id) => FieldId::Struct(*id),
                            };
                            fields.push((fid, v));
                        } else if let Some(fid) = self.map_cmd_field(cmd_id, f.ident) {
                            fields.push((fid, v));
                        }
                    }
                    self.emit(Publish { cmd_id, fields })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Emit(eff) => {
                if let Some(effect_id) = self.resolve_effect(eff.value.ident) {
                    let mut fields = Vec::with_capacity(eff.value.fields.len());
                    for f in &eff.value.fields {
                        let v = self.lower_expr(f.expr);
                        if let Some(res) = &f.resolved {
                            let fid = match res {
                                s::ResolvedField::Cmd(id) => FieldId::Command(*id),
                                s::ResolvedField::Effect(id) => FieldId::Effect(*id),
                                s::ResolvedField::Struct(id) => FieldId::Struct(*id),
                            };
                            fields.push((fid, v));
                        } else if let Some(fid) = self.map_effect_field(effect_id, f.ident) {
                            fields.push((fid, v));
                        }
                    }
                    self.emit(Emit { effect_id, fields })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Delete(d) => {
                if let Some((fact_id, key_filters, val_filters)) =
                    self.lower_fact_literal_filters(&d.fact)
                {
                    self.emit(Delete {
                        fact_id,
                        key_filters,
                        val_filters,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Update(u) => {
                if let Some((fact_id, keys, old_values)) = self.lower_fact_literal_filters(&u.fact)
                {
                    let mut new_values = Vec::with_capacity(u.to.len());
                    for f in &u.to {
                        match &f.expr {
                            s::FactField::Expr(eid) => {
                                let v = self.lower_expr(*eid);
                                new_values.push((f.ident, v));
                            }
                            s::FactField::Bind => {}
                        }
                    }
                    self.emit(Update {
                        fact_id,
                        keys,
                        old_values,
                        new_values,
                    })
                } else {
                    self.emit(Const {
                        val: ConstValue::Unit,
                    })
                }
            }
            s::ExprKind::Binary(op, l, r) => {
                let lv = self.lower_expr(*l);
                let rv = self.lower_expr(*r);
                let v = match op {
                    hir::BinOp::Add => self.emit(BinOp::Add(lv, rv)),
                    hir::BinOp::Sub => self.emit(BinOp::Sub(lv, rv)),
                    hir::BinOp::And => self.emit(BinOp::And(lv, rv)),
                    hir::BinOp::Or => self.emit(BinOp::Or(lv, rv)),
                    hir::BinOp::Eq => self.emit(BinOp::Eq(lv, rv)),
                    hir::BinOp::Neq => {
                        let eq = self.emit(BinOp::Eq(lv, rv));
                        self.emit(UnaryOp::Not(eq))
                    }
                    hir::BinOp::Gt => self.emit(BinOp::Gt(lv, rv)),
                    hir::BinOp::Lt => self.emit(BinOp::Lt(lv, rv)),
                    hir::BinOp::GtEq => self.emit(BinOp::GtEq(lv, rv)),
                    hir::BinOp::LtEq => self.emit(BinOp::LtEq(lv, rv)),
                };
                v
            }
            s::ExprKind::If {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond_v = self.lower_expr(*cond);
                let then_block = self.new_block();
                let else_block = self.new_block();
                let merge_block = self.new_block();
                self.terminate(Terminator::Branch(Branch {
                    cond: cond_v,
                    true_block: then_block,
                    false_block: else_block,
                }));

                self.set_current(then_block);
                let then_v = self.lower_expr(*then_expr);
                self.terminate(Terminator::Jump(merge_block));

                self.set_current(else_block);
                let else_v = self.lower_expr(*else_expr);
                self.terminate(Terminator::Jump(merge_block));

                self.set_current(merge_block);
                self.emit(Phi {
                    incoming: vec![(then_block, then_v), (else_block, else_v)],
                })
            }
            s::ExprKind::Block(bid) => {
                let exprs = &self.sh.blocks[*bid].exprs;
                let mut last = self.emit(Const {
                    val: ConstValue::Unit,
                });
                for &eid in exprs {
                    last = self.lower_expr(eid);
                }
                last
            }
            s::ExprKind::Return(e) => {
                let v = self.lower_expr(*e);
                self.terminate(Terminator::Return(v));
                v
            }
            // Side-effect and stmt forms
            s::ExprKind::Let(v) => {
                let value = self.lower_expr(v.value);
                self.bind(v.ident, value);
                self.emit(Const {
                    val: ConstValue::Unit,
                })
            }
            s::ExprKind::Discard(v) => {
                let _ = self.lower_expr(v.expr);
                self.emit(Const {
                    val: ConstValue::Unit,
                })
            }
            s::ExprKind::Check(v) => {
                // Branch on condition; on false, panic; on true, continue with unit
                let cond = self.lower_expr(v.expr);
                let true_block = self.new_block();
                let false_block = self.new_block();
                let merge_block = self.new_block();
                self.terminate(Terminator::Branch(Branch {
                    cond,
                    true_block,
                    false_block,
                }));

                // False path: panic
                self.set_current(false_block);
                self.terminate(Terminator::Panic);

                // True path: unit then jump to merge
                self.set_current(true_block);
                let unit_val = self.emit(Const {
                    val: ConstValue::Unit,
                });
                self.terminate(Terminator::Jump(merge_block));

                // Merge
                self.set_current(merge_block);
                // Single-incoming phi is fine as a join marker
                let _ = self.emit(Phi {
                    incoming: vec![(true_block, unit_val)],
                });
                unit_val
            }
            s::ExprKind::DebugAssert(v) => {
                let cond = self.lower_expr(v.expr);
                let true_block = self.new_block();
                let false_block = self.new_block();
                let merge_block = self.new_block();
                self.terminate(Terminator::Branch(Branch {
                    cond,
                    true_block,
                    false_block,
                }));

                self.set_current(false_block);
                self.terminate(Terminator::Panic);

                self.set_current(true_block);
                let unit_val = self.emit(Const {
                    val: ConstValue::Unit,
                });
                self.terminate(Terminator::Jump(merge_block));

                self.set_current(merge_block);
                let _ = self.emit(Phi {
                    incoming: vec![(true_block, unit_val)],
                });
                unit_val
            }
            // Remaining side-effect forms are placeholders for now
            // Unhandled kinds fall back to unit; expand as MIR grows
            _ => self.emit(Const {
                val: ConstValue::Unit,
            }),
        }
    }
}

/// Lowers a simplified IR expression into MIR SSA blocks and instructions.
pub fn lower_simplified_expr(
    sh: &s::Hir,
    hir: HirView<'_>,
    symbols: SymbolsView<'_>,
    root: s::ExprId,
) -> (SlotMap<BlockId, Block>, Vec<Inst>) {
    let mut ctx = SimplLowerCtx::new(sh, hir, symbols);
    let _ = ctx.lower_expr(root);
    (ctx.blocks, ctx.inst)
}
