---
policy-version: 3
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
            emit Result { x: x }
        }
        6 => {
            emit Result { x: x }
        }
    }
}
```