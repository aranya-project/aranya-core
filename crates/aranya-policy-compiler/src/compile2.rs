use std::collections::BTreeMap;

use aranya_policy_ast::Identifier;
use aranya_policy_module::{
    CodeMap, ExitReason, Instruction, Label, Module, ModuleData, ModuleV0, Value,
};

use crate::{
    ast::Ast,
    compile::{CompileError, Compiler},
    ctx::{Ctx, InnerCtx, Session},
    diag::DiagCtx,
};

type Result<T, E = CompileError> = std::result::Result<T, E>;

impl Compiler<'_> {
    /// TODO
    pub fn compile2(self) -> Result<Module> {
        let out = Output::default();

        let codemap = CodeMap::new(&self.policy.text, self.policy.ranges.clone());

        let sess = Session {
            dcx: DiagCtx::new(&self.policy.text, "TODO"),
        };
        let ast = Ast {
            ast: self.policy,
            schemas: self.ffi_modules,
            codemap: &codemap,
        };
        let inner = InnerCtx::new(&sess, ast);
        let mut _ctx = Ctx { inner: &inner };

        let mut cg = Codegen {
            prog: Vec::new(),
            codemap: Some(codemap),
            wp: 0,
            // c: 0,
            // is_debug: self.is_debug,
            // stub_ffi: self.stub_ffi,
        };

        // Panic when running a module without setup.
        cg.append_instruction(Instruction::Exit(ExitReason::Panic));

        let codemap = cg.codemap;

        Ok(Module {
            data: ModuleData::V0(ModuleV0 {
                progmem: out.prog.into_boxed_slice(),
                labels: out.labels,
                action_defs: BTreeMap::new(),
                command_defs: BTreeMap::new(),
                fact_defs: BTreeMap::new(),
                struct_defs: BTreeMap::new(),
                enum_defs: BTreeMap::new(),
                command_attributes: BTreeMap::new(),
                codemap,
                globals: out.globals,
            }),
        })
    }
}

#[derive(Clone, Debug, Default)]
struct Output {
    prog: Vec<Instruction>,
    labels: BTreeMap<Label, usize>,
    globals: BTreeMap<Identifier, Value>,
}

#[derive(Debug)]
struct Codegen {
    //out: &'a mut Output,
    prog: Vec<Instruction>,
    codemap: Option<CodeMap>,
    wp: usize,
    // c: usize,
    // is_debug: bool,
    // stub_ffi: bool,
}

impl Codegen {
    /// Append an instruction to the program memory, and increment the
    /// program counter. If no other PC manipulation has been done,
    /// this means that the program counter points to the new
    /// instruction.
    fn append_instruction(&mut self, i: Instruction) {
        self.prog.push(i);
        self.wp = self.wp.checked_add(1).expect("self.wp + 1 must not wrap");
    }
}
