---
policy-version: 1
---

<!--
This basic policy has the bare bones needed to make it function with the policy_vm.
Namely it uses the `TestFfiEnvelope` from the runtime vm_policy to supply the
minimal functionality needed to satisfy the seal and open blocks. Aside from that both
`basic-policy.md` and `ffi-policy.md` both contain the same on-graph commands,
Init, Create, Increment, and Decrement.

The policies also supply sample ephemeral commands, `AddSessionCmdToGraph`,
`GetStuff`, CreateGreeting and `VerifyGreeting`. Ephemeral (session) commands are
not added to the graph of commands and do not persist any changes to the factDB.

It should be noted that there is no syntactic differences between on-graph and
ephemeral commands currently. They could in theory be used interchangeably,
however they are almost always created with a particular flavor in mind.
-->

```policy
use envelope

// `Stuff` is the fact we will interact with in the on-graph commands. It writes
// a simple fact to the factDB.
fact Stuff[a int]=>{x int}

// `StuffHappened` is the effect we will emit from on-graph commands. It shares
// an interface with the Stuff fact.
effect StuffHappened {
    a int,
    x int,
}

// `Message` is one of the facts we will interact with in the ephemeral sessions.
fact Message[msg string]=>{value string}

// The `PersistedSessionCommand` fact will store an ephemeral session command
// as an on-graph fact.
fact PersistedSessionCommand[command_type string]=>{value bytes}

// `Greeting` is an effect we will emit from the `CreateGreeting` command.
effect Greeting {
    msg string,
}

// `Success` is a simple effect we can emit to our test to indicate that a command
// has succeeded.
effect Success {
    value bool,
}

// `Init` is an on-graph command that initializes a graph.
command Init {
    // Local variables for command
    fields {
        nonce int
    }

    // Seal and open blocks are required by the policy_vm to transform an envelope
    // into command fields and vice versa.
    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    // The policy block contains statements which query data and check its validity.
    policy {
        check this.nonce > 0
        finish {}
    }
}

// The `init` action takes a nonce variable and passes it to the Init command.
action init(nonce int) {
    publish Init {
        nonce: nonce,
    }
}

// `Create` is a on-graph command that will create a `Stuff` fact in the factDB.
command Create {
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

// The `create` action takes a value and passes it to the `Create` command. For
// simplicity sake, the fact key is hard codded in all our examples.
action create(v int) {
    publish Create{
        key_a: 1,
        value: v,
    }
}

// `Increment` is a on-graph command that will increase our test count by the
// value passed in.
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

// The `increment` action takes a value and passes it to the `Increment` command.
// For simplicity sake, the fact key is hard codded in all our examples.
action increment(v int) {
    publish Increment{
        key_a: 1,
        value: v,
    }
}

// `Decrement` is a on-graph command that will decrease our test count by the
// value passed in.
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

// The `decrement` action takes a value and passes it to the `Decrement` command.
// For simplicity sake, the fact key is hard codded in all our examples.
action decrement(v int) {
    publish Decrement{
        key_a: 1,
        value: v,
    }
}

// `GetStuff` is a ephemeral command that queries the contents of the `Stuff`
// fact and returns it in a `StuffHappened` effect. As pointed out elsewhere,
// there is absolutely nothing stopping us from using this command in an on-graph
// or ephemeral context.
command GetStuff {
    fields {
        key_a int,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: 1]=>{x: ?}
        finish {
            emit StuffHappened{a: this.key_a, x: stuff.x}
        }
    }
}

// `get_stuff` calls the `GetStuff` command with the hardcoded test key.
action get_stuff() {
    publish GetStuff {
        key_a: 1,
    }
}

// `CreateGreeting` is an ephemeral command that creates a fact that lives for
// the lifetime of the session it was called in.
command CreateGreeting {
    fields {
        key string,
        value string,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        finish {
            // Write the Message fact to the session factDB
            create Message[msg: this.key]=>{value: this.value}
            // Return our value
            emit Greeting{msg: this.value}
        }
    }
}

// The `create_greeting` action calls the command `CreateGreeting`. Passing in
// the hardcoded greeting key and the message value.
action create_greeting(v string) {
    publish CreateGreeting {
        key: "greeting",
        value: v,
    }
}

// `VerifyGreeting` is an ephemeral command that looks up the Message fact and
// compares the contents with the value passed in. It is meant to be used in
// conjunction with `CreateGreeting`, where CreateGreeting writes to the factDB
// and VerifyGreeting checks it's contents.
command VerifyGreeting {
    fields {
        key string,
        value string,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    // A command can write to a temporary session fact that will be available
    // within the same session. We can query the session factDB and do something
    // with that data.
    policy {
        let greeting = unwrap query Message[msg: this.key]=>{value: ?}
        // Check that the stored value in the Message fact we look up matches
        // the value passed into the command.
        check greeting.value == this.value
        finish {
            emit Success{value: true}
        }
    }
}

// The `verify_hello` action calls the command `VerifyGreeting` that will verify
// the Message fact contains "hello".
action verify_hello() {
    publish VerifyGreeting {
        key: "greeting",
        value: "hello",
    }
}

// `AddSessionCmdToGraph` will take a serialized byte command and add it to
// the factDB. This command is used to test storing a session command on-graph.
command AddSessionCmdToGraph {
    fields {
        key string,
        cmd bytes,
    }

    seal { return envelope::seal(serialize(this)) }
    open { return deserialize(envelope::open(envelope)) }

    policy {
        finish {
            create PersistedSessionCommand[command_type: this.key]=>{value: this.cmd}
            emit Success{value: true}
        }
    }
}

// `add_session_cmd_to_graph` will call AddSessionCmdToGraph with a command name
// and byte value.
action add_session_cmd_to_graph(key string, value bytes) {
    publish AddSessionCmdToGraph {
        key: key,
        cmd: value,
    }
}
```
