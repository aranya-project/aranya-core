---
policy-version: 2
---
```policy
struct Foo {
    a int,
    b string,
}

struct Bar {
    b string,
    a int,
}

function convert() struct Bar {
    return Foo { a: 1, b: "test" } as Bar
}
```