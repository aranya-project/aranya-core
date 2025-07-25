use std::{convert::Infallible, ops::ControlFlow};

use crate::hir::hir::{
    ActionArg, ActionDef, ActionId, Block, BlockId, CmdDef, CmdField, CmdFieldKind, CmdId,
    EffectDef, EffectField, EffectFieldId, EffectFieldKind, EffectId, EnumDef, EnumId, Expr,
    ExprId, ExprKind, FactDef, FactField, FactId, FactKey, FactLiteral, FactVal, FinishFuncArg,
    FinishFuncDef, FinishFuncId, FuncArg, FuncDef, FuncId, GlobalId, GlobalLetDef, Hir, Ident,
    IdentId, InternalFunction, MatchPattern, Stmt, StmtId, StmtKind, StructDef, StructField,
    StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
};

impl Hir {
    /// Walks all AST nodes.
    pub fn walk<'hir, V>(&'hir self, visitor: &mut V)
    where
        V: Visitor<'hir>,
    {
        self.walk_actions(visitor);
        self.walk_cmds(visitor);
        self.walk_effects(visitor);
        self.walk_enums(visitor);
        self.walk_facts(visitor);
        self.walk_finish_funcs(visitor);
        self.walk_funcs(visitor);
        self.walk_global_lets(visitor);
        self.walk_structs(visitor);
    }

    /// Walks all actions.
    pub fn walk_actions<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.actions.keys() {
            try_branch!(self.walk_action(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific action.
    pub fn walk_action<'hir, V>(&'hir self, id: ActionId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.actions[id];
        try_branch!(visitor.visit_action_def(def));
        for &id in &def.args {
            let arg = &self.action_args[id];
            try_branch!(visitor.visit_action_arg(arg));
            try_branch!(self.walk_ident(arg.ident, visitor));
            try_branch!(self.walk_vtype(arg.ty, visitor));
        }
        try_branch!(self.walk_block(def.block, visitor));
        V::Result::output()
    }

    /// Walks all commands.
    pub fn walk_cmds<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.cmds.keys() {
            try_branch!(self.walk_cmd(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific command.
    pub fn walk_cmd<'hir, V>(&'hir self, id: CmdId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.cmds[id];
        try_branch!(visitor.visit_cmd_def(def));
        for &id in &def.fields {
            let field = &self.cmd_fields[id];
            try_branch!(visitor.visit_cmd_field(field));
            match &field.kind {
                CmdFieldKind::Field { ident, ty } => {
                    try_branch!(self.walk_ident(*ident, visitor));
                    try_branch!(self.walk_vtype(*ty, visitor));
                }
                CmdFieldKind::StructRef(ident) => {
                    try_branch!(self.walk_ident(*ident, visitor));
                }
            }
        }
        try_branch!(self.walk_block(def.seal, visitor));
        try_branch!(self.walk_block(def.open, visitor));
        try_branch!(self.walk_block(def.policy, visitor));
        try_branch!(self.walk_block(def.recall, visitor));
        V::Result::output()
    }

    /// Walks all effects.
    pub fn walk_effects<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.effects.keys() {
            try_branch!(self.walk_effect(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific effect.
    pub fn walk_effect<'hir, V>(&'hir self, id: EffectId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.effects[id];
        try_branch!(visitor.visit_effect_def(def));
        for &id in &def.items {
            try_branch!(self.walk_effect_field(id, visitor));
        }
        V::Result::output()
    }

    fn walk_effect_field<'hir, V>(&'hir self, id: EffectFieldId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let field = &self.effect_fields[id];
        try_branch!(visitor.visit_effect_field(field));
        match &field.kind {
            EffectFieldKind::Field { ident, ty } => {
                try_branch!(self.walk_ident(*ident, visitor));
                try_branch!(self.walk_vtype(*ty, visitor));
            }
            EffectFieldKind::StructRef(ident) => {
                try_branch!(self.walk_ident(*ident, visitor));
            }
        }
        V::Result::output()
    }

    /// Walks all enums.
    pub fn walk_enums<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.enums.keys() {
            try_branch!(self.walk_enum(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific enum.
    pub fn walk_enum<'hir, V>(&'hir self, id: EnumId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.enums[id];
        try_branch!(visitor.visit_enum_def(def));
        V::Result::output()
    }

    /// Walks all facts.
    pub fn walk_facts<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.facts.keys() {
            try_branch!(self.walk_fact(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific fact.
    pub fn walk_fact<'hir, V>(&'hir self, id: FactId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.facts[id];
        try_branch!(visitor.visit_fact_def(def));
        for &key_id in &def.keys {
            let key = &self.fact_keys[key_id];
            try_branch!(visitor.visit_fact_key(key));
            try_branch!(self.walk_ident(key.ident, visitor));
            try_branch!(self.walk_vtype(key.ty, visitor));
        }
        for &val_id in &def.vals {
            let val = &self.fact_vals[val_id];
            try_branch!(visitor.visit_fact_value(val));
            try_branch!(self.walk_ident(val.ident, visitor));
            try_branch!(self.walk_vtype(val.ty, visitor));
        }
        V::Result::output()
    }

    /// Walks all finish functions.
    pub fn walk_finish_funcs<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.finish_funcs.keys() {
            try_branch!(self.walk_finish_func(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific finish function.
    pub fn walk_finish_func<'hir, V>(&'hir self, id: FinishFuncId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.finish_funcs[id];
        try_branch!(visitor.visit_finish_func_def(def));
        for &arg_id in &def.args {
            let arg = &self.finish_func_args[arg_id];
            try_branch!(visitor.visit_finish_func_arg(arg));
            try_branch!(self.walk_ident(arg.ident, visitor));
            try_branch!(self.walk_vtype(arg.ty, visitor));
        }
        for &stmt in &def.stmts {
            try_branch!(self.walk_stmt(stmt, visitor));
        }
        V::Result::output()
    }

    /// Walks all functions.
    pub fn walk_funcs<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.funcs.keys() {
            try_branch!(self.walk_func(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific function.
    pub fn walk_func<'hir, V>(&'hir self, id: FuncId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.funcs[id];
        try_branch!(visitor.visit_func_def(def));
        for &arg_id in &def.args {
            let arg = &self.func_args[arg_id];
            try_branch!(visitor.visit_func_arg(arg));
            try_branch!(self.walk_ident(arg.ident, visitor));
            try_branch!(self.walk_vtype(arg.ty, visitor));
        }
        try_branch!(self.walk_vtype(def.result, visitor));
        for &stmt in &def.stmts {
            try_branch!(self.walk_stmt(stmt, visitor));
        }
        V::Result::output()
    }

    /// Walks all global let statements.
    pub fn walk_global_lets<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.global_lets.keys() {
            try_branch!(self.walk_global_let(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific global let.
    pub fn walk_global_let<'hir, V>(&'hir self, id: GlobalId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.global_lets[id];
        try_branch!(visitor.visit_global_def(def));
        try_branch!(self.walk_expr(def.expr, visitor));
        V::Result::output()
    }

    /// Walks all structs.
    pub fn walk_structs<'hir, V>(&'hir self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for id in self.structs.keys() {
            try_branch!(self.walk_struct(id, visitor));
        }
        V::Result::output()
    }

    /// Walks a specific struct.
    pub fn walk_struct<'hir, V>(&'hir self, id: StructId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let def = &self.structs[id];
        try_branch!(visitor.visit_struct_def(def));
        for &id in &def.items {
            try_branch!(self.walk_struct_field(id, visitor));
        }
        V::Result::output()
    }

    fn walk_struct_field<'hir, V>(&'hir self, id: StructFieldId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let field = &self.struct_fields[id];
        try_branch!(visitor.visit_struct_field(field));
        match &field.kind {
            StructFieldKind::Field { ident, ty } => {
                try_branch!(self.walk_ident(*ident, visitor));
                try_branch!(self.walk_vtype(*ty, visitor));
            }
            StructFieldKind::StructRef(ident) => {
                try_branch!(self.walk_ident(*ident, visitor));
            }
        }
        V::Result::output()
    }

    /// Walks a block.
    pub fn walk_block<'hir, V>(&'hir self, id: BlockId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let block = &self.blocks[id];
        try_branch!(visitor.visit_block(block));
        for &stmt in &block.stmts {
            try_branch!(self.walk_stmt(stmt, visitor));
        }
        V::Result::output()
    }

    /// Walks an expression.
    pub fn walk_expr<'hir, V>(&'hir self, id: ExprId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let expr = &self.exprs[id];
        try_branch!(visitor.visit_expr(expr));
        match &expr.kind {
            ExprKind::Int | ExprKind::String | ExprKind::Bool => {}
            ExprKind::Optional(v) => {
                if let Some(&id) = v.as_ref() {
                    try_branch!(self.walk_expr(id, visitor));
                }
            }
            ExprKind::NamedStruct(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                for (ident, expr) in &v.fields {
                    try_branch!(self.walk_ident(*ident, visitor));
                    try_branch!(self.walk_expr(*expr, visitor));
                }
            }
            ExprKind::InternalFunction(v) => match v {
                InternalFunction::Query(fact) | InternalFunction::Exists(fact) => {
                    try_branch!(self.walk_fact_literal(fact, visitor));
                }
                InternalFunction::FactCount(_, _, fact) => {
                    try_branch!(self.walk_fact_literal(fact, visitor));
                }
                InternalFunction::If(a, b, c) => {
                    try_branch!(self.walk_expr(*a, visitor));
                    try_branch!(self.walk_expr(*b, visitor));
                    try_branch!(self.walk_expr(*c, visitor));
                }
                InternalFunction::Serialize(expr) | InternalFunction::Deserialize(expr) => {
                    try_branch!(self.walk_expr(*expr, visitor));
                }
            },
            ExprKind::FunctionCall(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                for &arg in &v.args {
                    try_branch!(self.walk_expr(arg, visitor));
                }
            }
            ExprKind::ForeignFunctionCall(v) => {
                try_branch!(self.walk_ident(v.module, visitor));
                try_branch!(self.walk_ident(v.ident, visitor));
                for &arg in &v.args {
                    try_branch!(self.walk_expr(arg, visitor));
                }
            }
            ExprKind::Identifier(v) => {
                try_branch!(self.walk_ident(*v, visitor));
            }
            ExprKind::EnumReference(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                try_branch!(self.walk_ident(v.value, visitor));
            }
            ExprKind::Add(lhs, rhs)
            | ExprKind::Sub(lhs, rhs)
            | ExprKind::And(lhs, rhs)
            | ExprKind::Or(lhs, rhs) => {
                try_branch!(self.walk_expr(*lhs, visitor));
                try_branch!(self.walk_expr(*rhs, visitor));
            }
            ExprKind::Dot(expr, ident) => {
                try_branch!(self.walk_expr(*expr, visitor));
                try_branch!(self.walk_ident(*ident, visitor));
            }
            ExprKind::Equal(lhs, rhs)
            | ExprKind::NotEqual(lhs, rhs)
            | ExprKind::GreaterThan(lhs, rhs)
            | ExprKind::LessThan(lhs, rhs)
            | ExprKind::GreaterThanOrEqual(lhs, rhs)
            | ExprKind::LessThanOrEqual(lhs, rhs) => {
                try_branch!(self.walk_expr(*lhs, visitor));
                try_branch!(self.walk_expr(*rhs, visitor));
            }
            ExprKind::Negative(expr)
            | ExprKind::Not(expr)
            | ExprKind::Unwrap(expr)
            | ExprKind::CheckUnwrap(expr) => {
                try_branch!(self.walk_expr(*expr, visitor));
            }
            ExprKind::Is(expr, _) => {
                try_branch!(self.walk_expr(*expr, visitor));
                // TODO: visit the other element.
            }
            ExprKind::Block(block, expr) => {
                try_branch!(self.walk_block(*block, visitor));
                try_branch!(self.walk_expr(*expr, visitor));
            }
            ExprKind::Substruct(expr, ident) => {
                try_branch!(self.walk_expr(*expr, visitor));
                try_branch!(self.walk_ident(*ident, visitor));
            }
            ExprKind::Match(expr) => {
                try_branch!(self.walk_expr(*expr, visitor));
            }
        }
        V::Result::output()
    }

    fn walk_fact_literal<'hir, V>(&'hir self, fact: &'hir FactLiteral, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        try_branch!(visitor.visit_fact_literal(fact));
        try_branch!(self.walk_ident(fact.ident, visitor));
        for (ident, field) in &fact.keys {
            try_branch!(self.walk_ident(*ident, visitor));
            try_branch!(self.walk_fact_field(field, visitor));
        }
        for (ident, field) in &fact.vals {
            try_branch!(self.walk_ident(*ident, visitor));
            try_branch!(self.walk_fact_field(field, visitor));
        }
        V::Result::output()
    }

    fn walk_fact_field<'hir, V>(&'hir self, field: &'hir FactField, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        match field {
            FactField::Expr(expr) => {
                try_branch!(self.walk_expr(*expr, visitor));
            }
            FactField::Bind => {}
        }
        V::Result::output()
    }

    /// Walks an identifier.
    pub fn walk_ident<'hir, V>(&'hir self, id: IdentId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let ident = &self.idents[id];
        try_branch!(visitor.visit_ident(ident));
        V::Result::output()
    }

    /// Walks a statement.
    pub fn walk_stmt<'hir, V>(&'hir self, id: StmtId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let stmt = &self.stmts[id];
        try_branch!(visitor.visit_stmt(stmt));
        match &stmt.kind {
            StmtKind::Let(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                try_branch!(self.walk_expr(v.expr, visitor));
            }
            StmtKind::Check(v) => {
                try_branch!(self.walk_expr(v.expr, visitor));
            }
            StmtKind::Match(v) => {
                try_branch!(self.walk_expr(v.expr, visitor));
                for arm in &v.arms {
                    match &arm.pattern {
                        MatchPattern::Default => {}
                        MatchPattern::Values(values) => {
                            for &expr in values {
                                try_branch!(self.walk_expr(expr, visitor));
                            }
                        }
                    }
                    for &stmt in &arm.stmts {
                        try_branch!(self.walk_stmt(stmt, visitor));
                    }
                }
            }
            StmtKind::If(v) => {
                for branch in &v.branches {
                    try_branch!(self.walk_expr(branch.expr, visitor));
                    for &stmt in &branch.stmts {
                        try_branch!(self.walk_stmt(stmt, visitor));
                    }
                }
                if let Some(else_block) = v.else_block {
                    try_branch!(self.walk_block(else_block, visitor));
                }
            }
            StmtKind::Finish(block) => {
                try_branch!(self.walk_block(*block, visitor));
            }
            StmtKind::Map(v) => {
                try_branch!(self.walk_fact_literal(&v.fact, visitor));
                try_branch!(self.walk_ident(v.ident, visitor));
                for &stmt in &v.stmts {
                    try_branch!(self.walk_stmt(stmt, visitor));
                }
            }
            StmtKind::Return(v) => {
                try_branch!(self.walk_expr(v.expr, visitor));
            }
            StmtKind::ActionCall(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                for &expr in &v.args {
                    try_branch!(self.walk_expr(expr, visitor));
                }
            }
            StmtKind::Publish(v) => {
                try_branch!(self.walk_expr(v.exor, visitor));
            }
            StmtKind::Create(v) => {
                try_branch!(self.walk_fact_literal(&v.fact, visitor));
            }
            StmtKind::Update(v) => {
                try_branch!(self.walk_fact_literal(&v.fact, visitor));
                for (ident, field) in &v.to {
                    try_branch!(self.walk_ident(*ident, visitor));
                    try_branch!(self.walk_fact_field(field, visitor));
                }
            }
            StmtKind::Delete(v) => {
                try_branch!(self.walk_fact_literal(&v.fact, visitor));
            }
            StmtKind::Emit(v) => {
                try_branch!(self.walk_expr(v.expr, visitor));
            }
            StmtKind::FunctionCall(v) => {
                try_branch!(self.walk_ident(v.ident, visitor));
                for &expr in &v.args {
                    try_branch!(self.walk_expr(expr, visitor));
                }
            }
            StmtKind::DebugAssert(v) => {
                try_branch!(self.walk_expr(v.expr, visitor));
            }
        }
        V::Result::output()
    }

    /// Walks a variable type.
    pub fn walk_vtype<'hir, V>(&'hir self, id: VTypeId, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        let ty = &self.types[id];
        try_branch!(visitor.visit_vtype(ty));
        match &ty.kind {
            VTypeKind::String
            | VTypeKind::Bytes
            | VTypeKind::Int
            | VTypeKind::Bool
            | VTypeKind::Id => {}
            VTypeKind::Struct(v) => {
                try_branch!(self.walk_ident(*v, visitor));
            }
            VTypeKind::Enum(v) => {
                try_branch!(self.walk_ident(*v, visitor));
            }
            VTypeKind::Optional(v) => {
                try_branch!(self.walk_vtype(*v, visitor));
            }
        }
        V::Result::output()
    }
}

/// Visits [`Node`]s in [`Hir`].
pub(crate) trait Visitor<'hir>: Sized {
    /// The result from a "visit_" method.
    type Result: VisitorResult;

    //
    // Actions
    //

    fn visit_action_def(&mut self, _def: &'hir ActionDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_arg(&mut self, _arg: &'hir ActionArg) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_stmt(&mut self, _stmt: &'hir Stmt) -> Self::Result {
        Self::Result::output()
    }

    //
    // Commands
    //

    fn visit_cmd_def(&mut self, _def: &'hir CmdDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_field(&mut self, _field: &'hir CmdField) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_seal(&mut self, _block: &'hir Block) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_open(&mut self, _block: &'hir Block) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_policy(&mut self, _block: &'hir Block) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_recall(&mut self, _block: &'hir Block) -> Self::Result {
        Self::Result::output()
    }

    //
    // Effects
    //

    fn visit_effect_def(&mut self, _def: &'hir EffectDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_effect_field(&mut self, _field: &'hir EffectField) -> Self::Result {
        Self::Result::output()
    }

    //
    // Enums
    //

    fn visit_enum_def(&mut self, _def: &'hir EnumDef) -> Self::Result {
        Self::Result::output()
    }

    //
    // Facts
    //

    fn visit_fact_def(&mut self, _def: &'hir FactDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_key(&mut self, _key: &'hir FactKey) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_value(&mut self, _val: &'hir FactVal) -> Self::Result {
        Self::Result::output()
    }

    //
    // Finish functions
    //

    fn visit_finish_func_def(&mut self, _def: &'hir FinishFuncDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_finish_func_arg(&mut self, _arg: &'hir FinishFuncArg) -> Self::Result {
        Self::Result::output()
    }
    fn visit_finish_func_stmt(&mut self, _stmt: &'hir Stmt) -> Self::Result {
        Self::Result::output()
    }

    //
    // Functions
    //

    fn visit_func_def(&mut self, _def: &'hir FuncDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_arg(&mut self, _arg: &'hir FuncArg) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_result(&mut self, _vtype: &'hir VType) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_stmt(&mut self, _stmt: &'hir Stmt) -> Self::Result {
        Self::Result::output()
    }

    //
    // Globals
    //

    fn visit_global_def(&mut self, _def: &'hir GlobalLetDef) -> Self::Result {
        Self::Result::output()
    }

    //
    // Structs
    //

    fn visit_struct_def(&mut self, _def: &'hir StructDef) -> Self::Result {
        Self::Result::output()
    }
    fn visit_struct_field(&mut self, _field: &'hir StructField) -> Self::Result {
        Self::Result::output()
    }

    //
    // Misc
    //

    fn visit_ident(&mut self, _ident: &'hir Ident) -> Self::Result {
        Self::Result::output()
    }
    fn visit_block(&mut self, _block: &'hir Block) -> Self::Result {
        Self::Result::output()
    }
    fn visit_expr(&mut self, _expr: &'hir Expr) -> Self::Result {
        Self::Result::output()
    }
    fn visit_stmt(&mut self, _stmt: &'hir Stmt) -> Self::Result {
        Self::Result::output()
    }
    fn visit_vtype(&mut self, _vtype: &'hir VType) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_literal(&mut self, _fact: &'hir FactLiteral) -> Self::Result {
        Self::Result::output()
    }
}

/// The result from a [`Visitor`] method.
pub(crate) trait VisitorResult {
    type Residual;

    fn output() -> Self;
    fn from_residual(residual: Self::Residual) -> Self;
    fn from_branch(b: ControlFlow<Self::Residual>) -> Self;
    fn branch(self) -> ControlFlow<Self::Residual>;
}

impl VisitorResult for () {
    type Residual = Infallible;

    fn output() -> Self {}
    fn from_residual(_: Self::Residual) -> Self {}
    fn from_branch(_: ControlFlow<Self::Residual>) -> Self {}
    fn branch(self) -> ControlFlow<Self::Residual> {
        ControlFlow::Continue(())
    }
}

impl<T> VisitorResult for ControlFlow<T> {
    type Residual = T;

    fn output() -> Self {
        ControlFlow::Continue(())
    }
    fn from_residual(residual: Self::Residual) -> Self {
        ControlFlow::Break(residual)
    }
    fn from_branch(b: Self) -> Self {
        b
    }
    fn branch(self) -> Self {
        self
    }
}

macro_rules! try_branch {
    ($e:expr) => {
        match $crate::hir::visit::VisitorResult::branch($e) {
            core::ops::ControlFlow::Continue(()) => (),
            #[allow(unreachable_code)]
            core::ops::ControlFlow::Break(r) => {
                return $crate::hir::visit::VisitorResult::from_residual(r);
            }
        }
    };
}
pub(crate) use try_branch;

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, ops::ControlFlow};

    use aranya_policy_ast as ast;

    use super::*;
    use crate::hir::hir::*;

    /// Enum representing all visitable items in the HIR
    #[derive(Clone, Debug)]
    enum Item {
        ActionDef(ActionDef),
        ActionArg(ActionArg),
        Block(Block),
        CmdDef(CmdDef),
        CmdField(CmdField),
        EffectDef(EffectDef),
        EffectField(EffectField),
        EnumDef(EnumDef),
        Expr(Expr),
        FactDef(FactDef),
        FactKey(FactKey),
        FactVal(FactVal),
        FactLiteral(FactLiteral),
        FinishFuncDef(FinishFuncDef),
        FinishFuncArg(FinishFuncArg),
        FuncDef(FuncDef),
        FuncArg(FuncArg),
        GlobalLetDef(GlobalLetDef),
        Ident(Ident),
        Stmt(Stmt),
        StructDef(StructDef),
        StructField(StructField),
        VType(VType),
    }

    /// A visitor that verifies the exact HIR nodes being visited
    struct ExactVisitor {
        expected: VecDeque<Item>,
    }

    impl ExactVisitor {
        fn new(expected: Vec<Item>) -> Self {
            Self {
                expected: expected.into(),
            }
        }

        fn assert_done(&self) {
            assert!(
                self.expected.is_empty(),
                "expected items not visited: {:?}",
                self.expected
            );
        }
    }

    impl<'hir> Visitor<'hir> for ExactVisitor {
        type Result = ();

        fn visit_action_def(&mut self, def: &'hir ActionDef) {
            match self.expected.pop_front() {
                Some(Item::ActionDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected ActionDef, got {:?}", other),
            }
        }

        fn visit_action_arg(&mut self, arg: &'hir ActionArg) {
            match self.expected.pop_front() {
                Some(Item::ActionArg(expected)) => assert_eq!(arg, &expected),
                other => panic!("Expected ActionArg, got {:?}", other),
            }
        }

        fn visit_block(&mut self, block: &'hir Block) {
            match self.expected.pop_front() {
                Some(Item::Block(expected)) => assert_eq!(block, &expected),
                other => panic!("Expected Block, got {:?}", other),
            }
        }

        fn visit_cmd_def(&mut self, def: &'hir CmdDef) {
            match self.expected.pop_front() {
                Some(Item::CmdDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected CmdDef, got {:?}", other),
            }
        }

        fn visit_cmd_field(&mut self, field: &'hir CmdField) {
            match self.expected.pop_front() {
                Some(Item::CmdField(expected)) => assert_eq!(field, &expected),
                other => panic!("Expected CmdField, got {:?}", other),
            }
        }

        fn visit_effect_def(&mut self, def: &'hir EffectDef) {
            match self.expected.pop_front() {
                Some(Item::EffectDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected EffectDef, got {:?}", other),
            }
        }

        fn visit_effect_field(&mut self, field: &'hir EffectField) {
            match self.expected.pop_front() {
                Some(Item::EffectField(expected)) => assert_eq!(field, &expected),
                other => panic!("Expected EffectField, got {:?}", other),
            }
        }

        fn visit_enum_def(&mut self, def: &'hir EnumDef) {
            match self.expected.pop_front() {
                Some(Item::EnumDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected EnumDef, got {:?}", other),
            }
        }

        fn visit_expr(&mut self, expr: &'hir Expr) {
            match self.expected.pop_front() {
                Some(Item::Expr(expected)) => assert_eq!(expr, &expected),
                other => panic!("Expected Expr, got {:?}", other),
            }
        }

        fn visit_fact_def(&mut self, def: &'hir FactDef) {
            match self.expected.pop_front() {
                Some(Item::FactDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected FactDef, got {:?}", other),
            }
        }

        fn visit_fact_key(&mut self, key: &'hir FactKey) {
            match self.expected.pop_front() {
                Some(Item::FactKey(expected)) => assert_eq!(key, &expected),
                other => panic!("Expected FactKey, got {:?}", other),
            }
        }

        fn visit_fact_value(&mut self, val: &'hir FactVal) {
            match self.expected.pop_front() {
                Some(Item::FactVal(expected)) => assert_eq!(val, &expected),
                other => panic!("Expected FactVal, got {:?}", other),
            }
        }

        fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) {
            match self.expected.pop_front() {
                Some(Item::FinishFuncDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected FinishFuncDef, got {:?}", other),
            }
        }

        fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) {
            match self.expected.pop_front() {
                Some(Item::FinishFuncArg(expected)) => assert_eq!(arg, &expected),
                other => panic!("Expected FinishFuncArg, got {:?}", other),
            }
        }

        fn visit_func_def(&mut self, def: &'hir FuncDef) {
            match self.expected.pop_front() {
                Some(Item::FuncDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected FuncDef, got {:?}", other),
            }
        }

        fn visit_func_arg(&mut self, arg: &'hir FuncArg) {
            match self.expected.pop_front() {
                Some(Item::FuncArg(expected)) => assert_eq!(arg, &expected),
                other => panic!("Expected FuncArg, got {:?}", other),
            }
        }

        fn visit_global_def(&mut self, def: &'hir GlobalLetDef) {
            match self.expected.pop_front() {
                Some(Item::GlobalLetDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected GlobalLetDef, got {:?}", other),
            }
        }

        fn visit_ident(&mut self, ident: &'hir Ident) {
            match self.expected.pop_front() {
                Some(Item::Ident(expected)) => assert_eq!(ident, &expected),
                other => panic!("Expected Ident, got {:?}", other),
            }
        }

        fn visit_stmt(&mut self, stmt: &'hir Stmt) {
            match self.expected.pop_front() {
                Some(Item::Stmt(expected)) => assert_eq!(stmt, &expected),
                other => panic!("Expected Stmt, got {:?}", other),
            }
        }

        fn visit_struct_def(&mut self, def: &'hir StructDef) {
            match self.expected.pop_front() {
                Some(Item::StructDef(expected)) => assert_eq!(def, &expected),
                other => panic!("Expected StructDef, got {:?}", other),
            }
        }

        fn visit_struct_field(&mut self, field: &'hir StructField) {
            match self.expected.pop_front() {
                Some(Item::StructField(expected)) => assert_eq!(field, &expected),
                other => panic!("Expected StructField, got {:?}", other),
            }
        }

        fn visit_vtype(&mut self, ty: &'hir VType) {
            match self.expected.pop_front() {
                Some(Item::VType(expected)) => assert_eq!(ty, &expected),
                other => panic!("Expected VType, got {:?}", other),
            }
        }

        fn visit_fact_literal(&mut self, fact: &'hir FactLiteral) {
            match self.expected.pop_front() {
                Some(Item::FactLiteral(expected)) => assert_eq!(fact, &expected),
                other => panic!("Expected FactLiteral, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_visitor_simple_action() {
        let mut hir = Hir::default();

        // Create empty block
        let block_id = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![],
        });

        // Create simple action
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![],
            block: block_id,
        });

        // Expected visit order
        let expected = vec![
            Item::ActionDef(hir.actions[action_id].clone()),
            Item::Block(hir.blocks[block_id].clone()),
        ];

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_action_with_args() {
        let mut hir = Hir::default();

        // Create action argument
        let arg_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("name"),
        });
        let arg_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::String,
        });
        let action_arg = hir.action_args.insert_with_key(|id| ActionArg {
            id,
            ident: arg_ident,
            ty: arg_type,
        });

        // Create check statement with expression
        let name_ident_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Identifier(arg_ident),
        });
        let empty_string_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::String,
        });
        let not_equal_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::NotEqual(name_ident_expr, empty_string_expr),
        });
        let check_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Check(CheckStmt {
                expr: not_equal_expr,
            }),
        });

        // Create block with check statement
        let block_id = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![check_stmt],
        });

        // Create action
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![action_arg],
            block: block_id,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::ActionDef(hir.actions[action_id].clone()));
        expected.push(Item::ActionArg(hir.action_args[action_arg].clone()));
        expected.push(Item::Ident(hir.idents[arg_ident].clone()));
        expected.push(Item::VType(hir.types[arg_type].clone()));
        expected.push(Item::Block(hir.blocks[block_id].clone()));
        expected.push(Item::Stmt(hir.stmts[check_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[not_equal_expr].clone()));
        expected.push(Item::Expr(hir.exprs[name_ident_expr].clone()));
        expected.push(Item::Ident(hir.idents[arg_ident].clone()));
        expected.push(Item::Expr(hir.exprs[empty_string_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_control_flow() {
        // Test that visitor can break early
        struct BreakOnSecondExpr {
            count: usize,
        }

        impl<'hir> Visitor<'hir> for BreakOnSecondExpr {
            type Result = ControlFlow<()>;

            fn visit_expr(&mut self, _: &'hir Expr) -> Self::Result {
                self.count += 1;
                if self.count >= 2 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
        }

        let mut hir = Hir::default();

        // Create multiple expressions
        let expr1 = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let expr2 = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let expr3 = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });

        // Create let statements
        let ident_a = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("a"),
        });
        let stmt1 = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Let(LetStmt {
                ident: ident_a,
                expr: expr1,
            }),
        });

        let ident_b = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("b"),
        });
        let stmt2 = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Let(LetStmt {
                ident: ident_b,
                expr: expr2,
            }),
        });

        let ident_c = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("c"),
        });
        let stmt3 = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Let(LetStmt {
                ident: ident_c,
                expr: expr3,
            }),
        });

        // Create function
        let result_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let _func_id = hir.funcs.insert_with_key(|id| FuncDef {
            id,
            args: vec![],
            result: result_type,
            stmts: vec![stmt1, stmt2, stmt3],
        });

        let mut visitor = BreakOnSecondExpr { count: 0 };
        hir.walk(&mut visitor);
        assert_eq!(visitor.count, 2); // Should have stopped at 2
    }

    #[test]
    fn test_visitor_struct_and_fields() {
        let mut hir = Hir::default();

        // Create struct fields
        let name_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("name"),
        });
        let name_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::String,
        });
        let name_field = hir.struct_fields.insert_with_key(|id| StructField {
            id,
            kind: StructFieldKind::Field {
                ident: name_ident,
                ty: name_type,
            },
        });

        let age_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("age"),
        });
        let age_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let age_field = hir.struct_fields.insert_with_key(|id| StructField {
            id,
            kind: StructFieldKind::Field {
                ident: age_ident,
                ty: age_type,
            },
        });

        // Create struct
        let struct_id = hir.structs.insert_with_key(|id| StructDef {
            id,
            items: vec![name_field, age_field],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::StructDef(hir.structs[struct_id].clone()));
        expected.push(Item::StructField(hir.struct_fields[name_field].clone()));
        expected.push(Item::Ident(hir.idents[name_ident].clone()));
        expected.push(Item::VType(hir.types[name_type].clone()));
        expected.push(Item::StructField(hir.struct_fields[age_field].clone()));
        expected.push(Item::Ident(hir.idents[age_ident].clone()));
        expected.push(Item::VType(hir.types[age_type].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_empty_hir() {
        let hir = Hir::default();

        let mut visitor = ExactVisitor::new(vec![]);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_nested_expressions() {
        let mut hir = Hir::default();

        // Create function arguments
        let x_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("x"),
        });
        let y_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("y"),
        });
        let int_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let x_arg = hir.func_args.insert_with_key(|id| FuncArg {
            id,
            ident: x_ident,
            ty: int_type,
        });
        let y_arg = hir.func_args.insert_with_key(|id| FuncArg {
            id,
            ident: y_ident,
            ty: int_type,
        });

        // Create nested expression: x + y > 10
        let x_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Identifier(x_ident),
        });
        let y_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Identifier(y_ident),
        });
        let add_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Add(x_expr, y_expr),
        });
        let ten_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let gt_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::GreaterThan(add_expr, ten_expr),
        });

        // Create return statement
        let return_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt { expr: gt_expr }),
        });

        // Create function
        let bool_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Bool,
        });
        let _func_id = hir.funcs.insert_with_key(|id| FuncDef {
            id,
            args: vec![x_arg, y_arg],
            result: bool_type,
            stmts: vec![return_stmt],
        });

        // Track all expressions visited
        struct ExprCollector {
            exprs: Vec<ExprKind>,
        }

        impl<'hir> Visitor<'hir> for ExprCollector {
            type Result = ();

            fn visit_expr(&mut self, expr: &'hir Expr) {
                self.exprs.push(expr.kind.clone());
            }
        }

        let mut collector = ExprCollector { exprs: Vec::new() };
        hir.walk(&mut collector);

        // Should have visited 5 expressions
        assert_eq!(collector.exprs.len(), 5);
    }

    #[test]
    fn test_visitor_enum_and_fact() {
        // Manually construct HIR with enums and facts
        let mut hir = Hir::default();

        // Create enum
        let enum_id = hir.enums.insert_with_key(|id| EnumDef { id });

        // Create fact with keys and values
        let key_ident_id = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("id"),
        });
        let key_type_id = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let fact_key_id = hir.fact_keys.insert_with_key(|id| FactKey {
            id,
            ident: key_ident_id,
            ty: key_type_id,
        });

        let val_ident_id = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("name"),
        });
        let val_type_id = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::String,
        });
        let fact_val_id = hir.fact_vals.insert_with_key(|id| FactVal {
            id,
            ident: val_ident_id,
            ty: val_type_id,
        });

        let fact_id = hir.facts.insert_with_key(|id| FactDef {
            id,
            keys: vec![fact_key_id],
            vals: vec![fact_val_id],
        });

        // Expected visit order
        let mut expected = Vec::new();
        
        // Enums are visited first
        expected.push(Item::EnumDef(hir.enums[enum_id].clone()));

        // Then facts
        expected.push(Item::FactDef(hir.facts[fact_id].clone()));
        expected.push(Item::FactKey(hir.fact_keys[fact_key_id].clone()));
        expected.push(Item::Ident(hir.idents[key_ident_id].clone()));
        expected.push(Item::VType(hir.types[key_type_id].clone()));
        expected.push(Item::FactVal(hir.fact_vals[fact_val_id].clone()));
        expected.push(Item::Ident(hir.idents[val_ident_id].clone()));
        expected.push(Item::VType(hir.types[val_type_id].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_command_with_all_blocks() {
        let mut hir = Hir::default();

        // Create command fields
        let field_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("value"),
        });
        let field_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let cmd_field = hir.cmd_fields.insert_with_key(|id| CmdField {
            id,
            kind: CmdFieldKind::Field {
                ident: field_ident,
                ty: field_type,
            },
        });

        // Create empty blocks for each command phase
        let seal_block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![],
        });
        let open_block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![],
        });
        let policy_block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![],
        });
        let recall_block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![],
        });

        let cmd_id = hir.cmds.insert_with_key(|id| CmdDef {
            id,
            fields: vec![cmd_field],
            seal: seal_block,
            open: open_block,
            policy: policy_block,
            recall: recall_block,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::CmdDef(hir.cmds[cmd_id].clone()));
        expected.push(Item::CmdField(hir.cmd_fields[cmd_field].clone()));
        expected.push(Item::Ident(hir.idents[field_ident].clone()));
        expected.push(Item::VType(hir.types[field_type].clone()));
        expected.push(Item::Block(hir.blocks[seal_block].clone()));
        expected.push(Item::Block(hir.blocks[open_block].clone()));
        expected.push(Item::Block(hir.blocks[policy_block].clone()));
        expected.push(Item::Block(hir.blocks[recall_block].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_effect_with_struct_ref() {
        let mut hir = Hir::default();

        // Create effect with both regular field and struct ref
        let field_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("status"),
        });
        let field_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Bool,
        });
        let regular_field = hir.effect_fields.insert_with_key(|id| EffectField {
            id,
            kind: EffectFieldKind::Field {
                ident: field_ident,
                ty: field_type,
            },
        });

        let struct_ref_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("UserData"),
        });
        let struct_ref_field = hir.effect_fields.insert_with_key(|id| EffectField {
            id,
            kind: EffectFieldKind::StructRef(struct_ref_ident),
        });

        let effect_id = hir.effects.insert_with_key(|id| EffectDef {
            id,
            items: vec![regular_field, struct_ref_field],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::EffectDef(hir.effects[effect_id].clone()));
        expected.push(Item::EffectField(hir.effect_fields[regular_field].clone()));
        expected.push(Item::Ident(hir.idents[field_ident].clone()));
        expected.push(Item::VType(hir.types[field_type].clone()));
        expected.push(Item::EffectField(hir.effect_fields[struct_ref_field].clone()));
        expected.push(Item::Ident(hir.idents[struct_ref_ident].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_global_let() {
        let mut hir = Hir::default();

        // Create a global let with an integer expression
        let expr_id = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let global_id = hir.global_lets.insert_with_key(|id| GlobalLetDef {
            id,
            expr: expr_id,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::GlobalLetDef(hir.global_lets[global_id].clone()));
        expected.push(Item::Expr(hir.exprs[expr_id].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_finish_function() {
        let mut hir = Hir::default();

        // Create finish function with argument and statement
        let arg_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("result"),
        });
        let arg_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::String,
        });
        let finish_arg = hir.finish_func_args.insert_with_key(|id| FinishFuncArg {
            id,
            ident: arg_ident,
            ty: arg_type,
        });

        // Create a check statement
        let check_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Bool,
        });
        let check_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Check(CheckStmt { expr: check_expr }),
        });

        let finish_id = hir.finish_funcs.insert_with_key(|id| FinishFuncDef {
            id,
            args: vec![finish_arg],
            stmts: vec![check_stmt],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::FinishFuncDef(hir.finish_funcs[finish_id].clone()));
        expected.push(Item::FinishFuncArg(hir.finish_func_args[finish_arg].clone()));
        expected.push(Item::Ident(hir.idents[arg_ident].clone()));
        expected.push(Item::VType(hir.types[arg_type].clone()));
        expected.push(Item::Stmt(hir.stmts[check_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[check_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_struct_with_mixed_fields() {
        let mut hir = Hir::default();

        // Create struct with regular field and struct ref
        let field_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("age"),
        });
        let field_type = hir.types.insert_with_key(|id| VType {
            id,
            kind: VTypeKind::Int,
        });
        let regular_field = hir.struct_fields.insert_with_key(|id| StructField {
            id,
            kind: StructFieldKind::Field {
                ident: field_ident,
                ty: field_type,
            },
        });

        let struct_ref_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("BaseStruct"),
        });
        let struct_ref = hir.struct_fields.insert_with_key(|id| StructField {
            id,
            kind: StructFieldKind::StructRef(struct_ref_ident),
        });

        let struct_id = hir.structs.insert_with_key(|id| StructDef {
            id,
            items: vec![regular_field, struct_ref],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::StructDef(hir.structs[struct_id].clone()));
        expected.push(Item::StructField(hir.struct_fields[regular_field].clone()));
        expected.push(Item::Ident(hir.idents[field_ident].clone()));
        expected.push(Item::VType(hir.types[field_type].clone()));
        expected.push(Item::StructField(hir.struct_fields[struct_ref].clone()));
        expected.push(Item::Ident(hir.idents[struct_ref_ident].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_match_statement() {
        let mut hir = Hir::default();

        // Create match expression
        let match_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });

        // Create pattern expressions
        let pattern1 = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let pattern2 = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });

        // Create arm statements
        let arm1_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt {
                expr: hir.exprs.insert_with_key(|id| Expr {
                    id,
                    kind: ExprKind::Bool,
                }),
            }),
        });
        let arm2_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt {
                expr: hir.exprs.insert_with_key(|id| Expr {
                    id,
                    kind: ExprKind::Bool,
                }),
            }),
        });

        // Create match statement
        let match_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Match(MatchStmt {
                expr: match_expr,
                arms: vec![
                    MatchArm {
                        pattern: MatchPattern::Values(vec![pattern1, pattern2]),
                        stmts: vec![arm1_stmt],
                    },
                    MatchArm {
                        pattern: MatchPattern::Default,
                        stmts: vec![arm2_stmt],
                    },
                ],
            }),
        });

        // Create a function to hold the match statement
        let _func_id = hir.funcs.insert_with_key(|id| FuncDef {
            id,
            args: vec![],
            result: hir.types.insert_with_key(|id| VType {
                id,
                kind: VTypeKind::Bool,
            }),
            stmts: vec![match_stmt],
        });

        // Expected visit order (only for the match part)
        let mut expected = Vec::new();
        expected.push(Item::FuncDef(hir.funcs[func_id].clone()));
        expected.push(Item::VType(hir.types[hir.funcs[func_id].result].clone()));
        expected.push(Item::Stmt(hir.stmts[match_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[match_expr].clone()));
        expected.push(Item::Expr(hir.exprs[pattern1].clone()));
        expected.push(Item::Expr(hir.exprs[pattern2].clone()));
        expected.push(Item::Stmt(hir.stmts[arm1_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[hir.stmts[arm1_stmt].kind.as_return().unwrap().expr].clone()));
        expected.push(Item::Stmt(hir.stmts[arm2_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[hir.stmts[arm2_stmt].kind.as_return().unwrap().expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_if_statement() {
        let mut hir = Hir::default();

        // Create if condition expression
        let if_cond = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Bool,
        });

        // Create if branch statement
        let if_stmt_inner = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt {
                expr: hir.exprs.insert_with_key(|id| Expr {
                    id,
                    kind: ExprKind::Int,
                }),
            }),
        });

        // Create else block
        let else_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt {
                expr: hir.exprs.insert_with_key(|id| Expr {
                    id,
                    kind: ExprKind::Int,
                }),
            }),
        });
        let else_block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![else_stmt],
        });

        // Create if statement
        let if_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::If(IfStmt {
                branches: vec![IfBranch {
                    expr: if_cond,
                    stmts: vec![if_stmt_inner],
                }],
                else_block: Some(else_block),
            }),
        });

        // Create function to hold if statement
        let _func_id = hir.funcs.insert_with_key(|id| FuncDef {
            id,
            args: vec![],
            result: hir.types.insert_with_key(|id| VType {
                id,
                kind: VTypeKind::Int,
            }),
            stmts: vec![if_stmt],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::FuncDef(hir.funcs[func_id].clone()));
        expected.push(Item::VType(hir.types[hir.funcs[func_id].result].clone()));
        expected.push(Item::Stmt(hir.stmts[if_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[if_cond].clone()));
        expected.push(Item::Stmt(hir.stmts[if_stmt_inner].clone()));
        expected.push(Item::Expr(hir.exprs[hir.stmts[if_stmt_inner].kind.as_return().unwrap().expr].clone()));
        expected.push(Item::Block(hir.blocks[else_block].clone()));
        expected.push(Item::Stmt(hir.stmts[else_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[hir.stmts[else_stmt].kind.as_return().unwrap().expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_fact_literal() {
        let mut hir = Hir::default();

        // Create identifiers for fact literal
        let fact_name = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("User"),
        });
        let key_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("id"),
        });
        let val_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("name"),
        });

        // Create expressions for fact fields
        let key_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let val_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::String,
        });

        // Create fact literal
        let fact_literal = FactLiteral {
            ident: fact_name,
            keys: vec![(key_ident, FactField::Expr(key_expr))],
            vals: vec![(val_ident, FactField::Expr(val_expr))],
        };

        // Create a statement that uses the fact literal
        let create_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Create(Create {
                fact: fact_literal.clone(),
            }),
        });

        // Create action to hold the statement
        let block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![create_stmt],
        });
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![],
            block,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::ActionDef(hir.actions[action_id].clone()));
        expected.push(Item::Block(hir.blocks[block].clone()));
        expected.push(Item::Stmt(hir.stmts[create_stmt].clone()));
        expected.push(Item::FactLiteral(fact_literal));
        expected.push(Item::Ident(hir.idents[fact_name].clone()));
        expected.push(Item::Ident(hir.idents[key_ident].clone()));
        expected.push(Item::Expr(hir.exprs[key_expr].clone()));
        expected.push(Item::Ident(hir.idents[val_ident].clone()));
        expected.push(Item::Expr(hir.exprs[val_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_all_statement_kinds() {
        let mut hir = Hir::default();

        // Create various statements
        let let_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("x"),
        });
        let let_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let let_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Let(LetStmt {
                ident: let_ident,
                expr: let_expr,
            }),
        });

        let publish_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::String,
        });
        let publish_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Publish(Publish { exor: publish_expr }),
        });

        let emit_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Bool,
        });
        let emit_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Emit(Emit { expr: emit_expr }),
        });

        let action_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("do_something"),
        });
        let action_arg = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let action_call_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::ActionCall(ActionCall {
                ident: action_ident,
                args: vec![action_arg],
            }),
        });

        let func_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("helper"),
        });
        let func_arg = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::String,
        });
        let func_call_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::FunctionCall(FunctionCall {
                ident: func_ident,
                args: vec![func_arg],
            }),
        });

        let debug_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Bool,
        });
        let debug_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::DebugAssert(DebugAssert { expr: debug_expr }),
        });

        // Create action to hold all statements
        let block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![
                let_stmt,
                publish_stmt,
                emit_stmt,
                action_call_stmt,
                func_call_stmt,
                debug_stmt,
            ],
        });
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![],
            block,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::ActionDef(hir.actions[action_id].clone()));
        expected.push(Item::Block(hir.blocks[block].clone()));
        
        // Let statement
        expected.push(Item::Stmt(hir.stmts[let_stmt].clone()));
        expected.push(Item::Ident(hir.idents[let_ident].clone()));
        expected.push(Item::Expr(hir.exprs[let_expr].clone()));
        
        // Publish statement
        expected.push(Item::Stmt(hir.stmts[publish_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[publish_expr].clone()));
        
        // Emit statement
        expected.push(Item::Stmt(hir.stmts[emit_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[emit_expr].clone()));
        
        // Action call statement
        expected.push(Item::Stmt(hir.stmts[action_call_stmt].clone()));
        expected.push(Item::Ident(hir.idents[action_ident].clone()));
        expected.push(Item::Expr(hir.exprs[action_arg].clone()));
        
        // Function call statement
        expected.push(Item::Stmt(hir.stmts[func_call_stmt].clone()));
        expected.push(Item::Ident(hir.idents[func_ident].clone()));
        expected.push(Item::Expr(hir.exprs[func_arg].clone()));
        
        // Debug assert statement
        expected.push(Item::Stmt(hir.stmts[debug_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[debug_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_map_statement() {
        let mut hir = Hir::default();

        // Create fact literal for map
        let fact_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("User"),
        });
        let fact_literal = FactLiteral {
            ident: fact_ident,
            keys: vec![],
            vals: vec![],
        };

        // Create binding identifier
        let bind_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("u"),
        });

        // Create inner statement
        let inner_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Bool,
        });
        let inner_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Check(CheckStmt { expr: inner_expr }),
        });

        // Create map statement
        let map_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Map(MapStmt {
                fact: fact_literal.clone(),
                ident: bind_ident,
                stmts: vec![inner_stmt],
            }),
        });

        // Create action to hold the map statement
        let block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![map_stmt],
        });
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![],
            block,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::ActionDef(hir.actions[action_id].clone()));
        expected.push(Item::Block(hir.blocks[block].clone()));
        expected.push(Item::Stmt(hir.stmts[map_stmt].clone()));
        expected.push(Item::FactLiteral(fact_literal));
        expected.push(Item::Ident(hir.idents[fact_ident].clone()));
        expected.push(Item::Ident(hir.idents[bind_ident].clone()));
        expected.push(Item::Stmt(hir.stmts[inner_stmt].clone()));
        expected.push(Item::Expr(hir.exprs[inner_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_update_statement() {
        let mut hir = Hir::default();

        // Create fact literal for update
        let fact_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("User"),
        });
        let key_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("id"),
        });
        let key_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let fact_literal = FactLiteral {
            ident: fact_ident,
            keys: vec![(key_ident, FactField::Expr(key_expr))],
            vals: vec![],
        };

        // Create update fields
        let update_ident = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("name"),
        });
        let update_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::String,
        });

        // Create update statement
        let update_stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Update(Update {
                fact: fact_literal.clone(),
                to: vec![(update_ident, FactField::Expr(update_expr))],
            }),
        });

        // Create action to hold the update statement
        let block = hir.blocks.insert_with_key(|id| Block {
            id,
            stmts: vec![update_stmt],
        });
        let action_id = hir.actions.insert_with_key(|id| ActionDef {
            id,
            args: vec![],
            block,
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::ActionDef(hir.actions[action_id].clone()));
        expected.push(Item::Block(hir.blocks[block].clone()));
        expected.push(Item::Stmt(hir.stmts[update_stmt].clone()));
        expected.push(Item::FactLiteral(fact_literal));
        expected.push(Item::Ident(hir.idents[fact_ident].clone()));
        expected.push(Item::Ident(hir.idents[key_ident].clone()));
        expected.push(Item::Expr(hir.exprs[key_expr].clone()));
        expected.push(Item::Ident(hir.idents[update_ident].clone()));
        expected.push(Item::Expr(hir.exprs[update_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    #[test]
    fn test_visitor_complex_expressions() {
        let mut hir = Hir::default();

        // Create various expression types
        let ident1 = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("x"),
        });
        let ident2 = hir.idents.insert_with_key(|id| Ident {
            id,
            ident: ast::ident!("y"),
        });

        // Create identifier expressions
        let x_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Identifier(ident1),
        });
        let y_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Identifier(ident2),
        });

        // Create binary expressions
        let add_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Add(x_expr, y_expr),
        });
        let int_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Int,
        });
        let gt_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::GreaterThan(add_expr, int_expr),
        });

        // Create unary expressions
        let not_expr = hir.exprs.insert_with_key(|id| Expr {
            id,
            kind: ExprKind::Not(gt_expr),
        });

        // Create statement with the expression
        let stmt = hir.stmts.insert_with_key(|id| Stmt {
            id,
            kind: StmtKind::Return(ReturnStmt { expr: not_expr }),
        });

        // Create function to hold the statement
        let _func_id = hir.funcs.insert_with_key(|id| FuncDef {
            id,
            args: vec![],
            result: hir.types.insert_with_key(|id| VType {
                id,
                kind: VTypeKind::Bool,
            }),
            stmts: vec![stmt],
        });

        // Expected visit order
        let mut expected = Vec::new();
        expected.push(Item::FuncDef(hir.funcs[func_id].clone()));
        expected.push(Item::VType(hir.types[hir.funcs[func_id].result].clone()));
        expected.push(Item::Stmt(hir.stmts[stmt].clone()));
        expected.push(Item::Expr(hir.exprs[not_expr].clone()));
        expected.push(Item::Expr(hir.exprs[gt_expr].clone()));
        expected.push(Item::Expr(hir.exprs[add_expr].clone()));
        expected.push(Item::Expr(hir.exprs[x_expr].clone()));
        expected.push(Item::Ident(hir.idents[ident1].clone()));
        expected.push(Item::Expr(hir.exprs[y_expr].clone()));
        expected.push(Item::Ident(hir.idents[ident2].clone()));
        expected.push(Item::Expr(hir.exprs[int_expr].clone()));

        let mut visitor = ExactVisitor::new(expected);
        hir.walk(&mut visitor);
        visitor.assert_done();
    }

    // Helper to check if StmtKind is a Return variant
    impl StmtKind {
        fn as_return(&self) -> Option<&ReturnStmt> {
            match self {
                StmtKind::Return(r) => Some(r),
                _ => None,
            }
        }
    }
}
