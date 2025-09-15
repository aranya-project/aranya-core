---
policy-version: 2
---

This basic policy has the bare bones needed to make it function with the policy_vm.
Namely it uses the `TestFfiEnvelope` from the runtime vm_policy to supply the
minimal functionality needed to satisfy the seal and open blocks. Aside from that both
`basic-policy.md` and `ffi-policy.md` both contain the same on-graph commands,
Init, Create, Increment, and Decrement.

This policy also supplies sample ephemeral commands, `AddSessionCmdToGraph`,
`GetStuff`, `CreateGreeting` and `VerifyGreeting`. Ephemeral (session) commands are
not added to the graph of commands and do not persist any changes to the factDB.
Hence, they are also not delivered through syncs and should be transmitted via
some other mechanism.

It should be noted that there is no syntactic difference between on-graph and
ephemeral commands currently. They could in theory be used interchangeably,
however they are almost always created with a particular flavor in mind.

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

// The `PersistedSessionData` fact is meant to store an ephemeral session command
// as a byte value in the FactDB.
fact PersistedSessionData[command_type string]=>{value bytes}

// `Greeting` is an effect we will emit from the `CreateGreeting` command.
effect Greeting {
    msg string,
}

// `Success` is a simple effect we can emit to our test to indicate that a command
// has succeeded.
effect Success {
    value bool,
}

// The `init` action takes a nonce variable and passes it to the Init command.
action init(nonce int) {
    publish Init {
        nonce: nonce,
    }
}

// `Init` is a command that initializes a graph.
command Init {
    // Local variables for command
    fields {
        nonce int
    }

    // Seal and open blocks are required by the policy_vm to transform an envelope
    // into command fields and vice versa.
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    // The policy block contains statements which query data and check its validity.
    policy {
        check this.nonce > 0
        // The finish block contains statements which mutate facts.
        finish {}
    }
}

// The `create` action takes a value and passes it to the `Create` command. For
// simplicity sake, the fact key is hard coded in all our examples.
action create_action(v int) {
    publish Create{
        key_a: 1,
        value: v,
    }
}

// `Create` is a command that will create a `Stuff` fact in the factDB and emit
// the `StuffHappened` effect back to the user.
command Create {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        finish {
            create Stuff[a: this.key_a]=>{x: this.value}
            emit StuffHappened{a: this.key_a, x: this.value}
        }
    }
}

ephemeral action create_action_ephemeral(v int) {
    publish CreateEphemeral {
        key_a: 1,
        value: v,
    }
}

ephemeral command CreateEphemeral {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        finish {
            create Stuff[a: this.key_a]=>{x: this.value}
            emit StuffHappened{a: this.key_a, x: this.value}
        }
    }
}

// The `increment` action takes a value and passes it to the `Increment` command.
// For simplicity sake, the fact key is hard coded in all our examples.
action increment(v int) {
    publish Increment{
        key_a: 1,
        value: v,
    }
}

// `Increment` is an on-graph command that will increase our test count by the
// value passed in.
command Increment {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

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

ephemeral action increment_ephemeral(v int) {
    publish IncrementEphemeral {
        key_a: 1,
        value: v,
    }
}

ephemeral command IncrementEphemeral {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

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

// The `decrement` action takes a value and passes it to the `Decrement` command.
// For simplicity sake, the fact key is hard coded in all our examples.
action decrement(v int) {
    publish Decrement{
        key_a: 1,
        value: v,
    }
}

// `Decrement` is an on-graph command that will decrease our test count by the
// value passed in.
command Decrement {
    fields {
        key_a int,
        value int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: this.key_a]=>{x: ?}
        let new_x = stuff.x - this.value

        finish {
            update Stuff[a: this.key_a]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, x: new_x}
        }
    }
}

// `get_stuff` calls the `GetStuff` command with the hardcoded test key.
ephemeral action get_stuff() {
    publish GetStuff {
        key_a: 1,
    }
}

// `GetStuff` is a command that queries the contents of the `Stuff` fact and
// returns it in a `StuffHappened` effect.
ephemeral command GetStuff {
    fields {
        key_a int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: 1]=>{x: ?}
        finish {
            emit StuffHappened{a: this.key_a, x: stuff.x}
        }
    }
}

action get_stuff_on_graph() {
    publish GetStuffOnGraph {
        key_a: 1,
    }
}

command GetStuffOnGraph {
    fields {
        key_a int,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        let stuff = unwrap query Stuff[a: 1]=>{x: ?}
        finish {
            emit StuffHappened{a: this.key_a, x: stuff.x}
        }
    }
}

// The `create_greeting` action calls the command `CreateGreeting`. Passing in
// the hardcoded greeting key and the message value.
ephemeral action create_greeting(v string) {
    publish CreateGreeting {
        key: "greeting",
        value: v,
    }
}

// `CreateGreeting` is an ephemeral command that creates a fact that lives for
// the lifetime of the session it was called in.
ephemeral command CreateGreeting {
    fields {
        key string,
        value string,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        finish {
            // Write the Message fact to the session factDB
            create Message[msg: this.key]=>{value: this.value}
            // Return our value
            emit Greeting{msg: this.value}
        }
    }
}

// The `verify_hello` action calls the command `VerifyGreeting` that will verify
// the Message fact contains "hello".
ephemeral action verify_hello() {
    publish VerifyGreeting {
        key: "greeting",
        value: "hello",
    }
}

// `VerifyGreeting` is an ephemeral command that looks up the Message fact and
// compares the contents with the value passed in. It is meant to be used in
// conjunction with `CreateGreeting`, where CreateGreeting writes to the factDB
// and VerifyGreeting checks it's contents.
ephemeral command VerifyGreeting {
    fields {
        key string,
        value string,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

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

action verify_hello_on_graph() {
    publish VerifyGreetingOnGraph {
        key: "greeting",
        value: "hello",
    }
}

command VerifyGreetingOnGraph {
    fields {
        key string,
        value string,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        let greeting = unwrap query Message[msg: this.key]=>{value: ?}
        check greeting.value == this.value
        finish {
            emit Success{value: true}
        }
    }
}


// `store_session_data` will call StoreSessionData with a command name
// and byte value.
action store_session_data(key string, value bytes) {
    publish StoreSessionData {
        key: key,
        cmd: value,
    }
}

// `StoreSessionData` will take serialized byte information and add it to
// the factDB in a `PersistedSessionData` fact.
command StoreSessionData {
    fields {
        key string,
        cmd bytes,
    }

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        finish {
            create PersistedSessionData[command_type: this.key]=>{value: this.cmd}
            emit Success{value: true}
        }
    }
}

// `Relationship` is an effect that will be emitted from `Link` commands
// in order to show parent-child relationships between commands
effect Relationship {
    parent_id id,
    command_id id
}

// Emits `Relationship` effects
command Link {
    // Local variables for command
    fields {}

    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }

    policy {
        finish {
            emit Relationship{parent_id: envelope.parent_id, command_id: envelope.command_id}
        }
    }
}

// Publishes multiple `Link` commands
action publish_multiple_commands() {
    publish Link{}
    publish Link{}
    publish Link{}
}
```
