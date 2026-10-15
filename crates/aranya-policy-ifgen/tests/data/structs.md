---
policy-version: 2
---

```policy
struct User {
    uid: id,
    name: string
}

struct Admin {
    +User,
    role: string
}

effect UserAdded {
    +User
}

base Base {
    get_key { return None }
}

command AddUser with Base {
    fields {
        +User
    }
    policy {
        finish {
            emit UserAdded { uid: this.uid }
        }
    }
}

action add_user(uid: id, name: string) {
    publish AddUser { uid, name }
}

action delete_user(admin: struct Admin, uid: id) {}
```
