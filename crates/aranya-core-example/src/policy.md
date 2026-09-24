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

## Init Command

The first command in the graph. Creates the owner device's signing
key fact and the Owner singleton. Because no DeviceSignPubKey exists
yet, seal/open inline the crypto using keys from the command fields.

```policy
base command(init) BaseInit {
    fields {
        owner_keys struct PublicKeys,
    }
    get_key {
        return Some(this.owner_keys.sign_key)
    }
}

command Init with BaseInit {
    fields {
        nonce int,
    }

    policy {
        let author_id = envelope::author_id(envelope)
        check author_id == idam::derive_device_id(this.owner_keys.ident_key) else test_fail("not authorized")

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

## Base Command

```policy
base command Base {
    get_key {
        return match query DeviceSignPubKey[device_id: author_id] {
            Some(f) => Some(f.key)
            None => None
        }
    }
}

base command(ephemeral) BaseEphemeral {
    get_key {
        return match query DeviceSignPubKey[device_id: author_id] {
            Some(f) => Some(f.key)
            None => None
        }
    }
}
```

## AddDevice Command

Only the owner can add new devices. Uses seal_command/open_envelope
since the owner's signing key is already in the fact DB.

```policy
command AddDevice with Base {
    attributes {
        priority: 100
    }

    fields {
        device_keys struct PublicKeys,
    }

    policy {
        let author_id = envelope::author_id(envelope)
        let owner = query Owner[] or recall reject()
        check author_id == owner.device_id else test_fail("not authorized")

        let new_device_id = idam::derive_device_id(this.device_keys.ident_key)
        check !exists DeviceSignPubKey[device_id: new_device_id] else test_fail("no key")

        let new_sign_key_id = idam::derive_sign_key_id(this.device_keys.sign_key)

        finish {
            create DeviceSignPubKey[device_id: new_device_id]=>{
                key_id: new_sign_key_id,
                key: this.device_keys.sign_key,
            }
            emit DeviceAdded{device_id: new_device_id}
        }
    }

    recall reject() {}
}
```

## Application Commands

```policy
command SetCounter with Base {
    attributes {
        priority: 50
    }

    fields {
        name int,
        value int,
    }

    policy {
        finish {
            create Counter[name: this.name]=>{value: this.value}
            emit CounterSet{name: this.name, value: this.value}
        }
    }
}

command IncrementCounter with Base {
    attributes {
        priority: 50
    }

    fields {
        name int,
        amount int,
    }

    policy {
        let counter = query Counter[name: this.name]=>{value: ?} or recall reject()
        let new_value = add(counter.value, this.amount) or recall reject()

        finish {
            update Counter[name: this.name]=>{value: counter.value} to {value: new_value}
            emit CounterIncremented{name: this.name, value: new_value}
        }
    }

    recall reject() {}
}
```

## Ephemeral Query

```policy
command GetCounter with BaseEphemeral {
    fields {
        name int,
    }

    policy {
        let counter = query Counter[name: this.name]=>{value: ?} or test_fail()
        finish {
            emit CounterValue{name: this.name, value: counter.value}
        }
    }
}
```

## Actions

```policy
action(init) init(owner_keys struct PublicKeys, nonce int) {
    publish Init { owner_keys, nonce }
}

action add_device(device_keys struct PublicKeys) {
    publish AddDevice { device_keys }
}

action set_counter(name int, value int) {
    publish SetCounter { name, value }
}

action increment_counter(name int, amount int) {
    publish IncrementCounter { name, amount }
}

action(ephemeral) get_counter(name int) {
    publish GetCounter { name }
}
```
