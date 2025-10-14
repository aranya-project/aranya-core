---
policy-version: 2
---

This policy facilitates the full use of the `envelope_ffi`. To do that we need to
introduce several supporting FFIs, `crypto_ffi`, `device_ffi`, `idam_ffi`,
`perspective_ffi`. Together they give us the necessary functionality to satisfy
the seal and open blocks. The key difference between this policy and the
`basic-policy.md` is that the basic policy is setup to use the `TestFfiEnvelope`.
Both policies however contain the same sets of on-graph commands, Init, Create, Increment,
and Decrement.

This policy also supplies sample ephemeral commands, `CreateGreeting` and
`VerifyGreeting`. Ephemeral (session) commands are not added to the graph of
commands and do not persist any changes to the factDB. Hence, they are also not
delivered through syncs and should be transmitted via some other mechanism.

```policy
use idam
use perspective
use device
use crypto
use envelope

fact Stuff[a int]=>{x int}

effect StuffHappened {
    a int,
    x int,
}

// `Message` is one of the facts we will interact with in the ephemeral sessions.
fact Message[msg string]=>{value string}

// `Greeting` is an effect we will emit from the `CreateGreeting` command.
effect Greeting {
    msg string,
}

// `Success` is a simple effect we can emit to our test to indicate that a command
// has succeeded.
effect Success {
    value bool,
}

// A device's public SigningKey.
fact DeviceSignKey[device_id id]=>{key_id id, key bytes}

// A device's public IdentityKey.
//
// NB: `key_id` is also the DeviceId.
fact DeviceIdentKey[device_id id]=>{key bytes}

// A device's set of public DeviceKeys
struct DeviceKeyBundle {
    device_id id,
    ident_pk bytes,
    sign_pk bytes,
}

// Data needed to add a new device to the team.
struct NewDevice {
    device_id id,
    ident_pk bytes,
    sign_pk_id id,
    sign_pk bytes,
}

// Returns the role string.
function Role_Device() string {
    return "Role::Device"
}

// Derives the key ID for each of the DeviceKeys in the bundle and
// checks that `device_id` matches the ID derived from `ident_pk`.
// (The IdentityKey's ID is the DeviceId.)
function authorized_device_key_ids(device_keys struct DeviceKeyBundle) struct NewDevice {
    let got_device_id = idam::derive_device_id(device_keys.ident_pk)

    check got_device_id == device_keys.device_id

    let sign_pk_id = idam::derive_sign_key_id(device_keys.sign_pk)

    return NewDevice {
        device_id: device_keys.device_id,
        ident_pk: device_keys.ident_pk,
        sign_pk_id: sign_pk_id,
        sign_pk: device_keys.sign_pk,
    }
}

// Seals a serialized basic command into an envelope, using the stored signing key for this device.
function seal_basic_command(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author_sign_sk_id = check_unwrap query DeviceSignKey[device_id: author_id]=>{key_id: ?, key: ?}
    let signed = crypto::sign(
        author_sign_sk_id.key_id,
        payload,
    )

    return envelope::new(
        author_id,
        signed.command_id,
        signed.signature,
        payload,
    )
}

// Opens a basic command from an envelope, using the author's stored signing key.
function open_basic_command(envelope_input struct Envelope) bytes {
    let author_id = envelope::author_id(envelope_input)
    let author_sign_pk = check_unwrap query DeviceSignKey[device_id: author_id]=>{key_id: ?, key: ?}

    let crypto_command = crypto::verify(
        author_sign_pk.key,
        envelope::payload(envelope_input),
        envelope::command_id(envelope_input),
        envelope::signature(envelope_input),
    )
    return crypto_command
}

action init(nonce int, sign_pk bytes) {
    publish Init {
        nonce: nonce,
        sign_pk: sign_pk,
    }
}

command Init {
    fields {
        nonce int,
        sign_pk bytes,
    }

    seal {
        let parent_id = perspective::head_id()
        let payload = serialize(this)
        let author_sign_sk_id = idam::derive_sign_key_id(this.sign_pk)

        let signed = crypto::sign(
            author_sign_sk_id,
            payload,
        )

        let author_id = device::current_device_id()

        return envelope::new(
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let author_id = envelope::author_id(envelope)
        let payload = envelope::payload(envelope)
        let cmd = deserialize(payload)
        let author_sign_pk = cmd.sign_pk

        let crypto_command = crypto::verify(
            author_sign_pk,
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(crypto_command)
    }

    policy {
        check this.nonce > 0
        finish {}
    }

}
action add_device_keys(ident_pk bytes, sign_pk bytes) {
    publish AddDeviceKeys {
        ident_pk: ident_pk,
        sign_pk: sign_pk,
    }
}

command AddDeviceKeys {
    fields {
        ident_pk bytes,
        sign_pk bytes,
    }

    seal {
        let parent_id = perspective::head_id()
        let payload = serialize(this)
        let author_sign_sk_id = idam::derive_sign_key_id(this.sign_pk)

        let signed = crypto::sign(
            author_sign_sk_id,
            payload,
        )

        let author_id = device::current_device_id()

        return envelope::new(
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let author_id = envelope::author_id(envelope)
        let payload = envelope::payload(envelope)
        let cmd = deserialize(payload)
        let author_sign_pk = cmd.sign_pk

        let crypto_command = crypto::verify(
            author_sign_pk,
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(crypto_command)
    }

    policy {
        let author = envelope::author_id(envelope)
        let device_id = idam::derive_device_id(this.ident_pk)
        check author == device_id

        let device_keys = DeviceKeyBundle {
            device_id: author,
            ident_pk: this.ident_pk,
            sign_pk: this.sign_pk,
        }

        let device = authorized_device_key_ids(device_keys)

        finish {
            create DeviceSignKey[device_id: device.device_id]=>{key_id: device.sign_pk_id, key: device.sign_pk}
            create DeviceIdentKey[device_id: device.device_id]=>{key: device.ident_pk}
        }
    }
}

action create_action(v int) {
    publish Create{
        key_a: 1,
        value: v,
    }
}

command Create {
    // Local variables for command
    fields {
        key_a int,
        value int,
    }

    seal { return seal_basic_command(serialize(this)) }
    open { return deserialize(open_basic_command(envelope)) }

    policy {
        finish {
            create Stuff[a: this.key_a]=>{x: this.value}
            emit StuffHappened{a: this.key_a, x: this.value}
        }
    }
}

action increment(v int) {
    publish Increment{
        key_a: 1,
        value: v,
    }
}

command Increment {
    fields {
        key_a int,
        value int,
    }

    seal { return seal_basic_command(serialize(this)) }
    open { return deserialize(open_basic_command(envelope)) }

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

action decrement(v int) {
    publish Decrement{
        key_a: 1,
        value: v,
    }
}

command Decrement {
    fields {
        key_a int,
        value int,
    }

    seal { return seal_basic_command(serialize(this)) }
    open { return deserialize(open_basic_command(envelope)) }


    policy {
        let stuff = unwrap query Stuff[a: this.key_a]=>{x: ?}
        let new_x = stuff.x - this.value

        finish {
            update Stuff[a: this.key_a]=>{x: stuff.x} to {x: new_x}
            emit StuffHappened{a: this.key_a, x: new_x}
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

    seal { return seal_basic_command(serialize(this)) }
    open { return deserialize(open_basic_command(envelope)) }

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

    seal { return seal_basic_command(serialize(this)) }
    open { return deserialize(open_basic_command(envelope)) }

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
```
