# Compiler Refactoring Plan: New AST Post-Processing and Semantic Analysis Stages

## Overview

This document outlines the comprehensive plan for refactoring the Aranya Policy Compiler to move dependency analysis and name resolution out of the IR stage into dedicated compiler phases. The new architecture introduces two new stages that execute before IR generation.

## Architecture Overview

### Current State
```
AST → IR (with embedded dependency analysis & name resolution) → Bytecode
```

### New Architecture
```
AST → Symbol Resolution → Semantic Analysis → IR Generation → Bytecode
         ↓                     ↓                    ↓
    Symbol Table         Dependency Graph     Clean IR
    + Resolved AST       + Type Information   (no analysis)
```

## Stage Responsibilities

### 1. Symbol Resolution Stage (`symbol_resolution/`)
**Purpose**: Build symbol table and resolve identifier references

**Responsibilities**:
- Walk AST and collect all top-level declarations
- Build hierarchical symbol table with proper scoping
- Resolve all identifier references to their declarations
- Detect shadowing violations (Policy Language v2 rules)
- Handle FFI symbol integration
- Produce `ResolvedAST` wrapper with resolution information

**Does NOT handle**:
- Dependency analysis (moved to semantic analysis)
- Type checking (moved to semantic analysis)
- Cycle detection (moved to semantic analysis)

### 2. Semantic Analysis Stage (`semantic_analysis/`)
**Purpose**: Type checking, dependency analysis, and semantic validation

**Responsibilities**:
- Build dependency graph from resolved AST and symbol table
- Perform topological sort to detect cycles
- Type check all expressions and statements
- Validate semantic rules (context violations, etc.)
- Produce `TypeCheckedAST` with complete type information
- Output topologically sorted declaration order

### 3. IR Generation Stage (`ir/` - modified)
**Purpose**: Generate intermediate representation from validated AST

**Responsibilities**:
- Generate IR from type-checked, dependency-sorted AST
- Pure code generation without analysis
- Assume all validation is complete

**Removed responsibilities**:
- `dependency.rs` - moved to semantic analysis
- `name_resolution.rs` - moved to symbol resolution

## Implementation Status

### ✅ Completed

#### Core Architecture
- [x] Created `symbol_resolution/` module structure
- [x] Created `semantic_analysis/` module structure
- [x] Implemented AST wrapper types (`ResolvedAST`, `TypeCheckedAST`)
- [x] Moved dependency graph construction to semantic analysis
- [x] Basic compilation pipeline integration

#### Symbol Resolution
- [x] `symbol_table.rs` - Complete symbol table implementation
- [x] `resolver.rs` - Main resolver with AST walking
- [x] `scope.rs` - Scope management with shadowing detection
- [x] `error.rs` - Comprehensive error types
- [x] FFI symbol integration
- [x] Reserved identifier validation

#### Semantic Analysis
- [x] `mod.rs` - Main analyzer coordination
- [x] `cycle_detector.rs` - Dependency graph analysis
- [x] `error.rs` - Semantic error types
- [x] Basic type checking framework
- [x] Semantic validation framework

#### Testing
- [x] Unit tests for symbol resolution
- [x] Unit tests for semantic analysis
- [x] Integration tests for both stages

## TODO List

### Phase 1: Complete AST Structure Integration (High Priority)

#### Symbol Resolution Fixes
- [ ] **Fix StructItem handling** (`symbol_resolution/resolver.rs:241, 279`)
  - Handle `StructItem<EffectFieldDefinition>` vs `StructItem<FieldDefinition>`
  - Implement proper field extraction from struct items
  - Add support for struct references (`StructItem::StructRef`)

- [ ] **Fix FFI Module structure** (`symbol_resolution/symbol_table.rs:55-77`)
  - Understand actual `Module.data` structure
  - Implement proper FFI symbol extraction
  - Add support for all FFI types (structs, enums, functions)

- [ ] **Complete GlobalLetStatement handling**
  - Remove `value_type` assumption (not in AST)
  - Implement type inference from expression
  - Add proper type annotation support

- [ ] **Fix identifier access patterns**
  - Ensure all `AstNode<T>` access uses `.inner.field` pattern
  - Update all declaration name extraction
  - Fix parameter and field access

#### Semantic Analysis Completion
- [ ] **Complete dependency graph building** (`semantic_analysis/mod.rs:build_dependency_graph`)
  - Analyze resolved AST to find actual dependencies
  - Build edges between declarations based on usage
  - Handle different dependency types (Type, FunctionCall, etc.)

- [ ] **Implement full type checking** (`semantic_analysis/type_checker.rs`)
  - Type inference for expressions
  - Type checking for all statement types
  - Function signature validation
  - Return type checking

- [ ] **Complete semantic validation** (`semantic_analysis/validator.rs`)
  - Context-sensitive validation
  - Statement validity checking
  - Policy language rule enforcement

### Phase 2: Enhanced Functionality (Medium Priority)

#### Advanced Symbol Resolution
- [ ] **Implement complete expression resolution**
  - Handle all expression types in Policy Language
  - Support for match expressions with pattern bindings
  - Block expression scoping
  - Complex type expressions

- [ ] **Add location tracking**
  - Preserve source locations throughout resolution
  - Enable precise error reporting
  - Support for IDE integration

- [ ] **Implement pattern matching support**
  - Pattern variable binding in match expressions
  - Destructuring patterns
  - Pattern exhaustiveness checking

#### Advanced Semantic Analysis
- [ ] **Complete type system implementation**
  - Type inference algorithm
  - Generic type support (if applicable)
  - Type compatibility checking
  - Struct field type validation

- [ ] **Advanced dependency analysis**
  - Detect recursive function calls
  - Analyze fact dependencies
  - Check for circular global dependencies
  - Validate forward references

- [ ] **Policy language specific validation**
  - Action context validation
  - Command policy/recall block validation
  - Fact key field validation (hashable types)
  - Effect emission validation

### Phase 3: Integration and Optimization (Medium Priority)

#### Compiler Pipeline Integration
- [ ] **Update main compilation pipeline** (`compile.rs`)
  - Replace existing dependency graph usage
  - Use new semantic analysis results
  - Remove old dependency/name resolution code

- [ ] **Performance optimization**
  - Minimize AST traversals
  - Optimize symbol table lookups
  - Cache frequently accessed information

- [ ] **Error reporting improvements**
  - Unified error reporting across stages
  - Better error messages with suggestions
  - Source location integration

#### IR Module Cleanup
- [ ] **Remove old analysis code**
  - Delete `ir/dependency.rs`
  - Delete `ir/name_resolution.rs`
  - Clean up remaining references

- [ ] **Simplify IR generation**
  - Remove embedded analysis logic
  - Assume pre-validated input
  - Focus on pure code generation

### Phase 4: Testing and Documentation (Low Priority)

#### Comprehensive Testing
- [ ] **End-to-end integration tests**
  - Full compilation pipeline tests
  - Error case testing
  - Performance benchmarks

- [ ] **Property-based testing**
  - Symbol resolution invariants
  - Dependency graph properties
  - Type system consistency

- [ ] **Policy language compliance testing**
  - v1 and v2 language feature tests
  - Edge case validation
  - Regression test suite

#### Documentation
- [ ] **API documentation**
  - Complete rustdoc for all public interfaces
  - Usage examples
  - Architecture decision documentation

- [ ] **Integration guide**
  - How to use new compiler stages
  - Migration guide from old system
  - Performance considerations

## Technical Debt and Improvements

### Current Limitations
1. **Simplified type checking** - Current implementation is minimal
2. **Incomplete dependency analysis** - Only basic framework exists
3. **Limited error recovery** - Fails fast on errors
4. **No incremental compilation** - Full reanalysis required

### Future Enhancements
1. **Incremental compilation support**
   - Cache symbol tables between compilations
   - Minimal reanalysis on changes
   - Dependency-based invalidation

2. **IDE integration features**
   - Hover information
   - Go-to-definition
   - Symbol search and references

3. **Advanced diagnostics**
   - Unused variable detection
   - Dead code elimination
   - Performance hints

## Migration Strategy

### Phase 1: Side-by-side Implementation (Current)
- New stages coexist with existing code
- No disruption to current functionality
- Gradual testing and validation

### Phase 2: Gradual Migration
- Feature flag to enable new stages
- Parallel validation of results
- Performance comparison

### Phase 3: Full Migration
- Replace old implementation
- Remove deprecated code
- Update all dependent systems

## Risk Assessment

### High Risk
- **AST structure mismatches** - Require careful alignment with actual AST
- **Performance impact** - Additional analysis passes may slow compilation
- **Backwards compatibility** - Must maintain existing behavior

### Medium Risk
- **Complex dependency analysis** - Requires deep understanding of Policy Language
- **Type system complexity** - Policy Language has unique type rules
- **Integration complexity** - Many dependent systems to update

### Low Risk
- **Testing coverage** - Can be addressed incrementally
- **Documentation** - Important but not blocking
- **Performance optimization** - Can be deferred

## Success Criteria

### Functional Requirements
1. **Correctness**: All existing functionality preserved
2. **Performance**: Compilation time within 10% of current
3. **Error Quality**: Better error messages with precise locations
4. **Maintainability**: Clean separation of concerns

### Technical Requirements
1. **Architecture**: Clear stage boundaries and responsibilities
2. **Extensibility**: Easy to add new analysis passes
3. **Testability**: Comprehensive test coverage
4. **Documentation**: Well-documented public interfaces

## Timeline Estimate

### Phase 1 (AST Integration): 2-3 weeks
- High complexity due to AST structure alignment
- Critical for basic functionality

### Phase 2 (Enhanced Functionality): 3-4 weeks
- Medium complexity, depends on Policy Language features
- Builds on Phase 1 foundation

### Phase 3 (Integration): 1-2 weeks
- Low complexity, mostly cleanup and optimization
- Depends on Phase 2 completion

### Phase 4 (Testing/Documentation): 1-2 weeks
- Medium complexity, can be done in parallel
- Important for maintainability

**Total Estimated Time: 7-11 weeks**

## Conclusion

This refactoring represents a significant improvement in the Aranya Policy Compiler architecture. The new design properly separates concerns, enables better error reporting, and provides a foundation for future enhancements. While there is substantial work remaining, the core architecture is sound and the implementation is progressing well.

The key next step is completing the AST structure integration in Phase 1, which will enable full functionality testing and validation of the new architecture.