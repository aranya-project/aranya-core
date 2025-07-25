# Comprehensive HIR Implementation Plan

## Executive Summary
The HIR currently exists but is not integrated into the compilation pipeline. The compiler is undergoing a major refactoring to introduce proper compilation phases: Symbol Resolution → Semantic Analysis → IR Generation. The HIR should be positioned between the Semantic Analysis and IR Generation phases as a proper intermediate representation.

## Phase 1: Complete HIR Integration (2-3 weeks)

### 1.1 Fix Platform-Specific Issues
- Remove `#![cfg(target_os = "windows")]` from tests
- Enable tests on all platforms
- Remove `#![allow(dead_code)]` attributes
- Ensure all HIR code compiles and runs properly

### 1.2 Complete Field Representations
- **Struct fields**: Store actual field data (name, type) instead of just IDs
- **Effect fields**: Store field definitions with proper type information
- **Command fields**: Preserve struct reference expansion information
- Add proper enum variant storage with values

### 1.3 Integrate HIR into Compilation Pipeline
- Position HIR generation after Semantic Analysis
- Input: TypeCheckedAST from semantic analysis
- Output: HIR for IR generation
- Update compile.rs to use: AST → Symbol Resolution → Semantic Analysis → HIR → IR → Bytecode

## Phase 2: Enhance HIR with Semantic Information (3-4 weeks)

### 2.1 Add Symbol Resolution Information
- Store resolved symbol references in HIR nodes
- Include declaration site information for each identifier use
- Add scope information to blocks
- Preserve binding information for pattern matching

### 2.2 Include Type Information
- Embed resolved types in expression nodes
- Add type annotations to all typed HIR nodes
- Include type inference results from semantic analysis
- Store type constraints and relationships

### 2.3 Add Control Flow Information
- Build control flow graph edges between blocks
- Mark entry/exit points for functions and actions
- Add predecessor/successor information
- Include dominator tree information for optimization

### 2.4 Dependency and Analysis Metadata
- Store dependency edges between declarations
- Include topological ordering from semantic analysis
- Add liveness information for variables
- Mark pure/impure functions

## Phase 3: Optimize HIR for Code Generation (2-3 weeks)

### 3.1 Simplify and Desugar Constructs
- Convert complex expressions to simpler forms
- Expand syntactic sugar (e.g., optional chaining)
- Normalize control flow structures
- Flatten nested expressions where beneficial

### 3.2 Add SSA-like Properties
- Introduce versioning for mutable bindings
- Make data flow explicit
- Enable easier optimization passes
- Support dead code elimination

### 3.3 Optimization-Ready Attributes
- Mark inline candidates
- Identify constant expressions
- Flag tail-recursive functions
- Annotate hot paths based on static analysis

## Phase 4: Improve HIR Infrastructure (2 weeks)

### 4.1 Enhanced Visitor Pattern
- Add pre/post-order traversal options
- Implement visitor combinators
- Support early termination
- Add parallel visiting capabilities

### 4.2 HIR Validation
- Implement HIR invariant checking
- Ensure well-formedness after transformations
- Add debug assertions for HIR consistency
- Create HIR pretty-printing for debugging

### 4.3 Testing and Documentation
- Comprehensive unit tests for all HIR operations
- Integration tests for AST→HIR→IR pipeline
- Property-based testing for HIR transformations
- Complete API documentation with examples

## Implementation Details

### HIR Node Enhancements

```rust
// Example of enhanced HIR expression with semantic info
pub struct Expr {
    pub id: ExprId,
    pub kind: ExprKind,
    pub ty: TypeId,           // Resolved type
    pub span: Span,           // Source location
    pub attrs: ExprAttrs,     // Optimization hints
}

pub struct ExprAttrs {
    pub pure: bool,           // Side-effect free
    pub constant: bool,       // Compile-time constant
    pub inline_hint: bool,    // Inline candidate
}

// Enhanced block with CFG info
pub struct Block {
    pub id: BlockId,
    pub stmts: Vec<StmtId>,
    pub terminator: Terminator,
    pub predecessors: Vec<BlockId>,
    pub scope: ScopeId,
}
```

### Key Milestones

1. **Week 1-2**: Platform fixes and basic integration
2. **Week 3-4**: Complete field representations
3. **Week 5-6**: Add semantic information
4. **Week 7-8**: Implement HIR optimizations
5. **Week 9-10**: Infrastructure improvements
6. **Week 11-12**: Testing and documentation

### Success Criteria

1. HIR fully integrated into compilation pipeline
2. All tests passing on all platforms
3. Semantic information preserved from earlier phases
4. HIR suitable for optimization passes
5. Performance within 5% of direct AST→IR compilation
6. Comprehensive test coverage (>90%)
7. Complete documentation for HIR usage

### Risk Mitigation

1. **Integration complexity**: Prototype with simple policies first
2. **Performance overhead**: Profile and optimize critical paths
3. **Breaking changes**: Maintain compatibility layer temporarily
4. **Semantic preservation**: Extensive validation testing
5. **Memory usage**: Monitor arena allocations and optimize

## Current Status

Based on recent changes:
- HIR structures have been updated with proper field representations for structs and effects
- `EffectField` and `StructField` now have proper `kind` enums with field data
- Arena nodes include `PartialEq` for testing
- Visitor pattern has been updated to use `try_branch!` macro
- Test infrastructure is being improved for exact node verification

This plan positions the HIR as a proper intermediate representation that bridges the gap between semantic analysis and code generation, making the compiler more modular and enabling future optimizations.