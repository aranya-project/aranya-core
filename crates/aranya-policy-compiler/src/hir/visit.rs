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
    use super::*;

    #[test]
    fn test_foo() {
        struct MyVisitor {}
        impl<'hir> Visitor<'hir> for MyVisitor {
            type Result = ();
            fn visit_expr(&mut self, _expr: &'hir Expr) -> Self::Result {}
            fn visit_block(&mut self, _block: &'hir Block) -> Self::Result {}
        }
        let mut v = MyVisitor {};
        let hir = Hir::default();
        hir.walk_actions(&mut v);
    }
}
