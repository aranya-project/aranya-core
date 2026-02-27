---
policy-version: 2
---

```policy
let g_int = 42
let g_bool = true

let g_string = "a\n\x01b"

let g_some = Some(42)
let g_none = None

let g_enum = Answer::No

let g_struct = Complex {
    m_int: 1,
    m_bool: false,
    m_string: "hello",
    m_some: Some(2),
    m_none: None,
    m_enum: Answer::Yes,
    m_struct: Simple { m_int: 3 }
}

enum Answer {
    Yes,
    No,
}

struct Complex {
    m_int int,
    m_bool bool,
    m_string string,
    m_some option[int],
    m_none option[int],
    m_enum enum Answer,
    m_struct struct Simple,
}

struct Simple {
    m_int int,
}
```
