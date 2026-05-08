---
policy-version: 2
---

# Example Policy

This policy implements a bare minimum policy that provides team initialization and  device
management.

```policy
// Import necessary FFIs
use device
use crypto
use envelope
use perspective
use idam
```

## Facts

```policy
// A device has an ID and a key. The key is used for signing commands.
fact Device[dev id]=>{key bytes}
```

## Envelope management

```policy
// General signing function. It creates an envelope with the given payload (a serialized command)
// and signing key.
function sign_command(payload bytes, key bytes) struct Envelope {
    let parent_id = perspective::head_id()
    let author_id = device::current_device_id()
    let author_sign_key_id = idam::derive_sign_key_id(key)
    let signed = crypto::sign(
        author_sign_key_id,
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

// General open function. Opens an envelope using the given signing key and returns the verified
// payload.
function open_command(e struct Envelope, key bytes) bytes {
    let payload = envelope::payload(e)

    let c = crypto::verify(
        key,
        envelope::parent_id(e),
        payload,
        envelope::command_id(e),
        envelope::signature(e),
    )
    return c
}

// Retrieves a device key by taking the current device ID and looking it up in the Device fact.
// This assumes that this mapping exists, and a proper implementation should check for errors.
function current_device_key() bytes {
    let author_id = device::current_device_id()
    let author_dev = check_unwrap query Device[dev: author_id]
    return author_dev.key
}

/// Retrieves a device key by taking the envelope author ID and looking it up in the Device fact.
// Like current_device_key() above, a proper implementation would check for errors as a
// malicious command could have an author ID not in our database.
function envelope_author_key(envelope struct Envelope) bytes {
    let author_id = envelope::author_id(envelope)
    let author_dev = check_unwrap query Device[dev: author_id]
    return author_dev.key
}
```

## Team Creation

This initializes a device with a given "owner key". This owner doesn't actually have any more
power than any other user, as there are no privilege levels in this policy, but they do become
the first device in the team. See `init.run`.

```policy
action init(owner_key bytes) {
    publish Init{
        owner_key: owner_key,
    }
}

effect TeamCreated {
    owner_dev id,
}

command Init {
    attributes {
        // The init command must have init priority
        init: true
    }

    fields {
        owner_key bytes,
    }

    // Note the special case for both seal and open here. The owner key is used explicitly rather
    // than a device key pulled from a fact, because that fact doesn't yet exist.
    seal { return sign_command(serialize(this), this.owner_key) }
    open {
        let owner_key = deserialize(envelope::payload(envelope)).owner_key
        return deserialize(open_command(envelope, owner_key))
    }

    policy {
        let device_id = device::current_device_id()
        finish {
            create Device[dev: device_id]=>{key: this.owner_key}
            emit TeamCreated {
                owner_dev: device_id,
            }
        }
    }
}
```

## Add User

Adding a user is a fairly simple operation of adding their key to the `Device` fact. Their device
ID is the id of this command. See `init.run`.

```policy
action add_user(new_user_key bytes) {
    publish AddUser {
        new_user_key: new_user_key
    }
}

effect UserAdded {
    dev id,
}

command AddUser {
    attributes {
        // All other commands have numerical priority. Higher numbers have priority over lower.
        priority: 100,
    }

    fields {
        new_user_key bytes,
    }

    seal {
        return sign_command(serialize(this), current_device_key())
    }
    open {
        return deserialize(open_command(envelope, envelope_author_key(envelope)))
    }

    policy {
        let dev_id = envelope::command_id(envelope)
        // Check that this device has not already been added
        check !exists Device[dev: dev_id]

        finish {
            create Device[dev: dev_id]=>{key: this.new_user_key}
            emit UserAdded {
                dev: dev_id,
            }
        }
    }
}
```

## Add Raw Device

This variation of `add_device()` specifies the device ID explicitly rather than deriving it from
the command. You probably wouldn't want to do this in a real policy, but it is useful here for
testing. See `add_raw_device.run`.

```policy
action add_raw_device(device_id id, device_key bytes) {
    publish AddDevice {
        device_id: device_id,
        device_key: device_key,
    }
}

command AddDevice {
    attributes {
        priority: 101,
    }

    fields {
        device_id id,
        device_key bytes,
    }

    seal {
        return sign_command(serialize(this), current_device_key())
    }
    open {
        return deserialize(open_command(envelope, envelope_author_key(envelope)))
    }

    policy {
        check !exists Device[dev: this.device_id]

        finish {
            create Device[dev: this.device_id]=>{key: this.device_key}
            emit UserAdded {
                dev: this.device_id,
            }
        }
    }
}
```

# Get Raw Device

This simply fetches the keys from the `Device` fact, or reports that the device is not found. See
`get_raw_device.run` and `get_raw_device_not_found.run`.

```policy
action get_raw_device(device_id id) {
    publish GetDevice {
        device_id: device_id,
    }
}

effect DeviceInfo {
    device_id id,
    device_key bytes,
}

effect DeviceNotFound {
    device_id id,
}

command GetDevice {
    attributes {
        priority: 10,
    }

    fields {
        device_id id,
    }

    seal {
        return sign_command(serialize(this), current_device_key())
    }
    open {
        return deserialize(open_command(envelope, envelope_author_key(envelope)))
    }

    policy {
        let device_q = query Device[dev: this.device_id]
        if device_q is Some {
            let device_info = unwrap device_q
            finish {
                emit DeviceInfo {
                    device_id: device_info.dev,
                    device_key: device_info.key,
                }
            }
        } else {
            finish {
                emit DeviceNotFound {
                    device_id: this.device_id,
                }
            }
        }
    }
}
```

## Hello Message

In a proper policy, this would have an action to publish the command, but it is used as an example
of using a raw command struct in `hello.run`.

```policy
effect Message {
    msg string,
}

command Hello {
    attributes {
        priority: 0,
    }

    fields {
        msg string,
    }

    seal {
        return sign_command(serialize(this), current_device_key())
    }
    open {
        return deserialize(open_command(envelope, envelope_author_key(envelope)))
    }

    policy {
        finish {
            emit Message {
                msg: this.msg
            }
        }
    }
}
```
