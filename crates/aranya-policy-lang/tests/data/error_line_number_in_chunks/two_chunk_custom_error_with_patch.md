---
policy-version: 2
---

```policy
    let z = add(1, 2)
```

This next chunk contains an "invalid" operator error that suggests
code to fix it.
This tests that span(s) for the "patched" code snippets
are within the proper bounds even when using multiple policy chunks.
```policy
    function add(x int, y int) int {
        return x + y
    }
```
