---
policy-version: 3
---

<!--
This basic policy has the bare bones needed to make it function with the policy_vm.
Namely it uses the `TestFfiEnvelope` from the runtime vm_policy to supply the
minimal functionality to the seal and open blocks. Aside from that both
`basic-policy.md` and `ffi-policy.md` both contain the same actions, Init, Create,
Increment, and Decrement.
-->

```policy
fact Stuff[a int]=>{x int}

effect StuffHappened {
    a int,
    x int,
}

command Init {
    fields {
        nonce int
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        check this.nonce > 0
        finish {}
    }
}

action init(nonce int) {
    publish Init {
        nonce: nonce,
    }
}

command Create {
    // Local variables for command
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        finish {
            create Stuff[a: this.key_a]=>{x: this.value}
            emit StuffHappened{a: this.key_a, x: this.value}
        }
    }
}

action create(v int) {
    publish Create{
        key_a: 1,
        value: v,
    }
}

command Increment {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: this.key_a]=>{x: ?}
        let new_x = stuff.x + this.value
        check new_x < 25
        finish {
            update Stuff[a: this.key_a]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, x: new_x}
        }
    }
}

action increment(v int) {
    publish Increment{
        key_a: 1,
        value: v,
    }
}

command Decrement {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: this.key_a]=>{x: ?}
        let new_x = stuff.x - this.value
        finish {
            update Stuff[a: this.key_a]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, x: new_x}
        }
    }
}

action decrement(v int) {
    publish Decrement{
        key_a: 1,
        value: v,
    }
}
```
