---
policy-version: 3
---
```policy
fact Foo[v int]=>{}

effect Bar {
    x int
}

command Foo {
    fields {
        a int,
        b int,
    }
    policy {
        check this.a > 0
        finish {
            create Foo[v: this.b]=>{}
            effect Bar{
                x: this.a
            }
        }
    }
}

action foo(b int) {
    let x = if b == 0 then 4 else 3
    let y = Foo{
        a: x,
        b: 4
    }
    emit y
}
```
