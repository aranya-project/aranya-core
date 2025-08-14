# Type Checking Module

This module implements type checking for the Aranya policy language compiler.

## Overview

The type checker performs a single-pass traversal of the HIR (High-level Intermediate Representation) using the Visitor pattern. It computes and validates types for all expressions and statements, ensuring type safety before code generation.

## Algorithm

### Single-Pass Type Checking

The type checker uses a depth-first traversal with the following approach:

1. **Pre-order processing**: When entering scopes (functions, blocks), we push a new type environment
2. **Post-order processing**: When visiting expressions, we compute their types after their children have been typed
3. **Type environments**: Maintain a stack of environments for nested scopes

### Core Components

#### TypeChecker

The main visitor struct that walks the HIR and computes types:

- `hir`: Reference to the HIR
- `symbols`: Symbol table from the resolution pass
- `types`: Arena for allocating new types
- `expr_types`: Maps each ExprId to its computed Type
- `env_stack`: Stack of type environments for scope management
- `errors`: Collected type errors for reporting

#### Type Environment

Each scope has its own environment containing:
- Local variable bindings (IdentId → Type)
- Access to parent scope via the environment stack

### Expression Type Checking

Expressions are typed in post-order (after their children):

1. **Literals**: Direct type mapping
   - `String(_)` → `Type::String`
   - `Int(_)` → `Type::Int`
   - `Bool(_)` → `Type::Bool`
   - `Optional(None)` → `Type::Optional(fresh_type_var)`
   - `Optional(Some(e))` → `Type::Optional(type_of(e))`

2. **Identifiers**: Two-phase lookup
   - First check type environment stack (local variables)
   - Then check symbol table (global definitions)
   - ICE if not found (should be impossible after symbol resolution)

3. **Binary Operations**: Type constraints
   - Arithmetic (`+`, `-`): Both operands must be `Int` → `Int`
   - Logical (`&&`, `||`): Both operands must be `Bool` → `Bool`
   - Comparison (`==`, `!=`): Same type on both sides → `Bool`
   - Relational (`<`, `>`, `<=`, `>=`): Both `Int` → `Bool`

4. **Unary Operations**: Type constraints
   - Negation (`-`): Operand must be `Int` → `Int`
   - Logical NOT (`!`): Operand must be `Bool` → `Bool`
   - Unwrap (`!`, `?!`): Operand must be `Optional(T)` → `T`

5. **Function Calls**: Signature matching
   - Resolve function identifier to symbol
   - Check argument count matches parameters
   - Verify each argument type matches parameter type
   - Result is the function's return type

6. **Field Access** (`expr.field`):
   - Expression must have struct type
   - Field must exist in struct definition
   - Result is the field's type

7. **Enum References** (`Enum::Variant`):
   - Enum must exist in symbol table
   - Variant must exist in enum definition
   - Result is the enum type

### Statement Type Checking

1. **Let Statements**: Type inference
   - Type check the expression
   - Bind the variable with the expression's type
   - No explicit type annotations in the language

2. **Check Statements**: Boolean constraint
   - Expression must have type `Bool`

3. **Return Statements**: Return type matching
   - Expression type must match function's declared return type
   - Error if in void context

4. **Control Flow** (if/match):
   - Conditions must be `Bool` (for if)
   - All branches must have compatible types
   - Each branch gets its own scope

### Scope Management

The type checker maintains a stack of type environments:

1. **Global scope**: Top-level definitions (pushed first, popped last)
2. **Function scope**: Function parameters and body
3. **Block scope**: Local blocks, if branches, match arms

Variable lookup proceeds from innermost scope to outermost.

### Error Handling

Type errors are collected, not fatal:
- Type mismatches include expected and found types
- All errors include source spans for diagnostics
- ICE (Internal Compiler Error) only for impossible states

### Special Cases

1. **Optional Types**: `Optional(T)` where T is inferred from context
2. **Struct Literals**: Fields must match declaration exactly
3. **Fact Operations**: Keys and values must match fact schema
4. **FFI Functions**: Use declared signatures from FFI modules

## Invariants

The type checker maintains these invariants:

1. Every `IdentId` and `SymbolId` exists in the symbol table (or ICE)
2. Every expression gets exactly one type in `expr_types`
3. The environment stack is never empty during traversal
4. No implicit type conversions - types must match exactly
5. All code paths in non-void functions must return the correct type

## Implementation Notes

- We don't support recursive types or functions (prevented by earlier passes)
- Let bindings have no type annotations - types are always inferred
- The symbol resolution pass has already validated that all identifiers resolve
- Type equality is structural, not nominal (except for structs/enums which use SymbolId)