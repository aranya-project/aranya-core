---
policy-version: 2
---

# Minimal aranya-core Policy

A minimal policy demonstrating real crypto FFIs: device onboarding,
command signing/verification, and application-level facts.

## Imports

```policy
use crypto
use device
use envelope
use idam
use perspective
```

## Data Structures

```policy
struct PublicKeys {
    ident_key bytes,
    sign_key bytes,
    enc_key bytes,
}
```

## Facts

```policy
// Signing public key for seal/open verification.
fact DeviceSignPubKey[device_id id]=>{key_id id, key bytes}

// Singleton: tracks the team owner's device ID.
fact Owner[]=>{device_id id}

// Application data: a named counter.
fact Counter[name int]=>{value int}
```

## Effects

```policy
effect Initialized {
    device_id id,
}

effect DeviceAdded {
    device_id id,
}

effect CounterSet {
    name int,
    value int,
}

effect CounterIncremented {
    name int,
    value int,
}

effect CounterValue {
    name int,
    value int,
}
```

## Base Cryptography

Signs and verifies commands using the author's DeviceSignPubKey fact.

```policy
// Signs the payload using the current device's Device Signing Key,
// then packages the data and signature into an Envelope.
function seal_command(payload bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author_sign_pk = check_unwrap query DeviceSignPubKey[device_id: author_id]

    let signed = crypto::sign(author_sign_pk.key_id, payload)
    return envelope::new(
        parent_id,
        author_id,
        signed.command_id,
        signed.signature,
        payload,
    )
}

// Opens an envelope using the author's public Device Signing Key.
function open_envelope(sealed_envelope struct Envelope) bytes {
    let author_id = envelope::author_id(sealed_envelope)
    let author_sign_pk = check_unwrap query DeviceSignPubKey[device_id: author_id]

    let verified_command = crypto::verify(
        author_sign_pk.key,
        envelope::parent_id(sealed_envelope),
        envelope::payload(sealed_envelope),
        envelope::command_id(sealed_envelope),
        envelope::signature(sealed_envelope),
    )
    return verified_command
}
```

## Init Command

The first command in the graph. Creates the owner device's signing
key fact and the Owner singleton. Because no DeviceSignPubKey exists
yet, seal/open inline the crypto using keys from the command fields.

```policy
command Init {
    attributes {
        init: true
    }

    fields {
        owner_keys struct PublicKeys,
        nonce int,
    }

    seal {
        let parent_id = perspective::head_id()
        let author_id = device::current_device_id()
        let payload = serialize(this)
        let author_sign_key_id = idam::derive_sign_key_id(this.owner_keys.sign_key)

        let signed = crypto::sign(author_sign_key_id, payload)
        return envelope::new(
            parent_id,
            author_id,
            signed.command_id,
            signed.signature,
            payload,
        )
    }

    open {
        let payload = envelope::payload(envelope)
        let author_sign_key = deserialize(payload).owner_keys.sign_key

        let verified_command = crypto::verify(
            author_sign_key,
            envelope::parent_id(envelope),
            payload,
            envelope::command_id(envelope),
            envelope::signature(envelope),
        )
        return deserialize(verified_command)
    }

    policy {
        let author_id = envelope::author_id(envelope)
        check author_id == idam::derive_device_id(this.owner_keys.ident_key)

        let sign_key_id = idam::derive_sign_key_id(this.owner_keys.sign_key)

        finish {
            create DeviceSignPubKey[device_id: author_id]=>{
                key_id: sign_key_id,
                key: this.owner_keys.sign_key,
            }
            create Owner[]=>{device_id: author_id}
            emit Initialized{device_id: author_id}
        }
    }
}
```

## AddDevice Command

Only the owner can add new devices. Uses seal_command/open_envelope
since the owner's signing key is already in the fact DB.

```policy
command AddDevice {
    attributes {
        priority: 100
    }

    fields {
        device_keys struct PublicKeys,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let author_id = envelope::author_id(envelope)
        let owner = unwrap query Owner[]
        check author_id == owner.device_id

        let new_device_id = idam::derive_device_id(this.device_keys.ident_key)
        check !exists DeviceSignPubKey[device_id: new_device_id]

        let new_sign_key_id = idam::derive_sign_key_id(this.device_keys.sign_key)

        finish {
            create DeviceSignPubKey[device_id: new_device_id]=>{
                key_id: new_sign_key_id,
                key: this.device_keys.sign_key,
            }
            emit DeviceAdded{device_id: new_device_id}
        }
    }
}
```

## Application Commands

```policy
command SetCounter {
    attributes {
        priority: 50
    }

    fields {
        name int,
        value int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        finish {
            create Counter[name: this.name]=>{value: this.value}
            emit CounterSet{name: this.name, value: this.value}
        }
    }
}

command IncrementCounter {
    attributes {
        priority: 50
    }

    fields {
        name int,
        amount int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let counter = unwrap query Counter[name: this.name]=>{value: ?}
        let new_value = unwrap add(counter.value, this.amount)

        finish {
            update Counter[name: this.name]=>{value: counter.value} to {value: new_value}
            emit CounterIncremented{name: this.name, value: new_value}
        }
    }
}
```

## Ephemeral Query

```policy
ephemeral command GetCounter {
    fields {
        name int,
    }

    seal { return seal_command(serialize(this)) }
    open { return deserialize(open_envelope(envelope)) }

    policy {
        let counter = unwrap query Counter[name: this.name]=>{value: ?}
        finish {
            emit CounterValue{name: this.name, value: counter.value}
        }
    }
}
```

## Actions

```policy
action init(owner_keys struct PublicKeys, nonce int) {
    publish Init {
        owner_keys: owner_keys,
        nonce: nonce,
    }
}

action add_device(device_keys struct PublicKeys) {
    publish AddDevice {
        device_keys: device_keys,
    }
}

action set_counter(name int, value int) {
    publish SetCounter {
        name: name,
        value: value,
    }
}

action increment_counter(name int, amount int) {
    publish IncrementCounter {
        name: name,
        amount: amount,
    }
}

ephemeral action get_counter(name int) {
    publish GetCounter {
        name: name,
    }
}
```
