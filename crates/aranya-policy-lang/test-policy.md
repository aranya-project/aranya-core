---
policy-version: 2
---
```policy
command Result {
    fields {
        x int
    }
}

action foo() {
    let x = 6

    match x {
        5 => {
            publish Result { x: x }
        }
        6 => {
            publish Result { x: x }
        }
    }
}
```