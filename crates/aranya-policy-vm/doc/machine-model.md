# Stack

The stack contains a sequence of values. Values can only be created or destroyed on the top of the stack, but some instructions may move items around within the stack.

## Data types

The stack can hold these types:

| name     | type                  |
|----------|-----------------------|
| int      | 64-bit signed integer |
| bool     | boolean               |
| string   | A UTF-8 string        |
| struct   | A named struct (see lang spec) |
| fact     | A fact (see lang spec) |
| none     | An empty optional value |

In particular, there is no explicit optional type, as they are elided during compilation.

# Control Flow Stack

The `call` and `return` instructions push and pop addresses from a secondary and otherwise inaccessible stack, the control flow stack.

# Instructions

All instructions can be prefixed with a label, but labels can only be jumped to with particular instructions.

## Stack Description Conventions

| name     | type |
|----------|------|
|`x`, `y`  |numbers|
|`a`, `b`  |bools|
|`s`       |a string|
|`n`       |identifier|
|`t`       |a struct|
|`v`, `w`  |any value|
|`f`       |a fact|
|`i`       |an id|
|`z`       |an opaque value|

## data/stack
||||
|-|-|-|
| `const(v)`   | `( -- v )`         | push a value onto the stack
| `def`        | `( v s -- )`       | define a local value by name
| `get`        | `( s -- v )`       | get a value by name
| `dup`        | `( v -- v v )` | duplicate the item at the top of the stack
| `pop`        | `( v -- )`         | remove a value from the top of the stack

## control flow
||||
|-|-|-|
|`block`...`end` | `( -- )`           | define a block
|`jump(L)`       | `( -- )`           | jump forward to label L in the current block
|`branch(L)`     | `( b -- )`         | `jump` if `b` is true
|`next`          | `( -- )`           | jump to the beginning of the block
|`last`          | `( -- )`           | jump to the end of the block
|`call`          | `( s -- )`         | call regular function with name s
|`return`        | `( -- )`           | return to the last address on the control flow stack
|`exit`          | `( ! )`            | End execution non-fatally
|`panic`         | `( ! )`            | terminate execution fatally

## arithmetic/logic
||||
|-|-|-|
|`add`          | `( x y -- x+y )`     | add `x` to `y`
|`sub`          | `( x y -- x-y )`     | subtract `y` from `x`
|`not`          | `( a -- !a )`        | logical negation of a
|`gt`           | `( a b -- a&gt;b )`  | true if `a` is greater than `b`, else false
|`lt`           | `( a b -- a&lt;b )`  | true if `a` is less than `b`, else false
|`eq`           | `( a b -- a=b )`     | true if `a` is equal to `b`, else false
|`as(n)`        | `( t -- t' )`        | replace a struct value with an equivalent struct of the given type

## facts
||||
|-|-|-|
|`fact.new`     | `( s -- f )`         | create a fact object of the given name
|`fact.kset`    | `( f v s -- f )`     | set a key member (overwrites any existing entry)
|`fact.vset`    | `( f v s -- f )`     | set a value member (overwrites any existing entry)

## structs
||||
|-|-|-|
|`struct.new`       | `( s -- t )`                                              | Create a struct object of the given name
|`struct.set`       | `( t v s -- t )`                                          | Add member `name` to `s` with value `v`
|`struct.get`       | `( t s -- v )`                                            | Get member `name` from `s`
|`struct.mset(n)`   | `( t (s v) (repeated n times) -- t)`                      | Add members to struct `t` by consuming n pairs of names and values
|`struct.mget(n)`   | `(t s (repeated n times) -- (s v) (repeated n times)`     | Get n key/value pairs from struct `t` from n member names

## context-specific
||||
|-|-|-|
|`publish`      | `( s -- )`           | publish a command struct
|`create`       | `( f -- )`           | create a fact
|`delete`       | `( f -- )`           | delete a fact
|`update`       | `( f f -- )`         | update a fact
|`emit`         | `( s -- )`           | emit an effect struct
|`query`        | `( f -- s )`         | execute a fact query
|`exists`       | `( f -- b )`         | determine whether or not the fact exists
|`fact_count`   | `( x f -- y )`       | count facts (up to a limit) matching a given query
|`id`           | `( z -- i )`         | get the `id` of a command
|`author.id`    | `( z -- i )`         | get the `id` of the author of a command

# Examples

## Create a fact and execute a query on it

```
query Foo[x: 3]=>{y: ?}
```

```
// instruction            stack after instruction execution
const "Foo"               "Foo"
fact.new                  Foo[]=>{}
const "x"                 Foo[]=>{} "x"
const 3                   Foo[]=>{} "x" 3
fact.kset                 Foo[x: 3]=>{}
query                     Foo[x: 3]=>{y: 4}
```
