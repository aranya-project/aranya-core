---
policy-version: 2
---

```policy
fact Device[dev id]=>{key bytes}
```

```policy
use device
use crypto
use envelope
use perspective
use idam

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

function current_device_key() bytes {
    let author_id = device::current_device_id()
    let author_dev = check_unwrap query Device[dev: author_id]
    return author_dev.key
}

function envelope_author_key(envelope struct Envelope) bytes {
    let author_id = envelope::author_id(envelope)
    let author_dev = check_unwrap query Device[dev: author_id]
    return author_dev.key
}
```

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
        init: true
    }

    fields {
        owner_key bytes,
    }

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
