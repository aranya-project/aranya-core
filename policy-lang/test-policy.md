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
        check self.a > 0
        finish {
            create Foo[v: self.b]=>{}
            effect Bar{
                x: self.a
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
