---
policy-version: 2
---

```policy
struct User {
    uid id,
    name string
}

struct Admin {
    +User,
    role string
}

effect UserAdded {
    +User
}

command AddUser {
    fields {
        +User
    }
    seal { return todo() }
    open { return todo() }
    policy {
        finish {
            emit UserAdded { uid: this.uid }
        }
    }
}

action add_user(uid id, name string) {
    publish AddUser {
        uid: uid,
        name: name
    }
}

action delete_user(admin struct Admin, uid id) {}
```
