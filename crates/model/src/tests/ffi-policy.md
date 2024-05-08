---
policy-version: 1
---

<!--
This policy facilitates the use of the `envelope_ffi`. To do that we need to
introduce several supporting FFIs, `crypto_ffi`, `device_ffi`, `idam_ffi`,
`perspective_ffi`. Together they give us the necessary functionality to satisfy
the seal and open blocks. The key difference between this policy and the
`basic-policy.md` is that the basic policy is setup to use the `TestFfiEnvelope`.
Both policies however contain the same set of actions, Init, Create, Increment,
and Decrement.
-->

```policy
fact Stuff[a int]=>{x int}

effect StuffHappened {
    a int,
    x int,
}

// A user's public SigningKey.
fact UserSignKey[user_id id]=>{key_id id, key bytes}

// A user's public IdentityKey.
//
// NB: `key_id` is also the UserID.
fact UserIdentKey[user_id id]=>{key bytes}

// A user's set of public UserKeys
struct UserKeyBundle {
    user_id id,
    ident_pk bytes,
    sign_pk bytes,
}

// Data needed to add a new user to the team.
struct NewUser {
    user_id id,
    ident_pk bytes,
    sign_pk_id id,
    sign_pk bytes,
}

// Returns the role string.
function Role_User() string {
    return "Role::User"
}

// Derives the key ID for each of the UserKeys in the bundle and
// checks that `user_id` matches the ID derived from `ident_pk`.
// (The IdentityKey's ID is the UserID.)
function authorized_user_key_ids(user_keys struct UserKeyBundle) struct NewUser {
    let got_user_id = idam::derive_user_id(user_keys.ident_pk)

    check got_user_id == user_keys.user_id

    let sign_pk_id = idam::derive_sign_key_id(user_keys.sign_pk)

    return NewUser {
        user_id: user_keys.user_id,
        ident_pk: user_keys.ident_pk,
        sign_pk_id: sign_pk_id,
        sign_pk: user_keys.sign_pk,
    }
}

// Seals a serialized basic command into an envelope, using the stored signing key for this device.
function seal_basic_command(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_user_id()
    let author_sign_sk_id = check_unwrap query UserSignKey[user_id: author_id]=>{key_id: ?, key: ?}
    let signed = crypto::sign(
        author_sign_sk_id.key_id,
        payload,
    )

    return envelope::new(
        parent_id,
        author_id,
        signed.command_id,
        signed.signature,
        payload,
    )
}

// Opens a basic command from an envelope, using the author's stored signing key.
function open_basic_command(envelope struct Envelope) bytes {
    let author_id = envelope::author_id(envelope)
    let author_sign_pk = check_unwrap query UserSignKey[user_id: author_id]=>{key_id: ?, key: ?}
    let parent_id = envelope::parent_id(envelope)

    let command = crypto::verify(
        author_sign_pk.key,
        parent_id,
        envelope::payload(envelope),
        envelope::command_id(envelope),
        envelope::signature(envelope),
    )
    return command
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

        let author_id = device::current_user_id()

        return envelope::new(
            parent_id,
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let author_id = envelope::author_id(envelope)
        let parent_id = envelope::parent_id(envelope)
        let payload = envelope::payload(envelope)
        let cmd = deserialize(payload)
        let author_sign_pk = cmd.sign_pk

        let command = crypto::verify(
            author_sign_pk,
            parent_id,
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(command)
    }

    policy {
        check this.nonce > 0
        finish {}
    }

}
action add_user_keys(ident_pk bytes, sign_pk bytes) {
    publish AddUserKeys {
        ident_pk: ident_pk,
        sign_pk: sign_pk,
    }
}

command AddUserKeys {
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

        let author_id = device::current_user_id()

        return envelope::new(
            parent_id,
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let author_id = envelope::author_id(envelope)
        let parent_id = envelope::parent_id(envelope)
        let payload = envelope::payload(envelope)
        let cmd = deserialize(payload)
        let author_sign_pk = cmd.sign_pk

        let command = crypto::verify(
            author_sign_pk,
            parent_id,
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(command)
    }

    policy {
        let author = envelope::author_id(envelope)
        let user_id = idam::derive_user_id(this.ident_pk)
        check author == user_id

        let user_keys = UserKeyBundle {
            user_id: author,
            ident_pk: this.ident_pk,
            sign_pk: this.sign_pk,
        }

        let user = authorized_user_key_ids(user_keys)

        finish {
            create UserSignKey[user_id: user.user_id]=>{key_id: user.sign_pk_id, key: user.sign_pk}
            create UserIdentKey[user_id: user.user_id]=>{key: user.ident_pk}
        }
    }
}

action create(v int) {
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
```
