---
policy-version: 2
---

# TT&C Policy

## Setup

```
use braid
use crypto
use device
```

## Devices and Roles

The TT&C Team has the following roles:

### Owner

The Owner role is initially assigned when the TT&C team is
created (see [`CreateTtcTeam`](#createttcteam)). They are only
allowed to:

- Add other Owners
- Add Admins
- Remove themselves
- Remove Admins
- Remove Operators
- Remove Satellites
- Revoke AFC labels from Operators
- Revoke AFC labels from Satellites

The Owner role should _not_ be regularly used. Instead, use
the [Admin](#admin) role for day-to-day operations.

### Admin

Admins manage Operators. They are only allowed to:

- Add Operators
- Add Satellites
- Remove Operators
- Remove Satellites
- Decide which satellites Operators are allowed to manage

### Operator

Operators operator and control individal satellites. They
are only allowed to:

- Create AFC channels with individual satellites as specified by
  Admins.

### Satellite

Satellites are individual satellites. They are only allowed to:

- Create AFC channels with Operators as specified by
  Admins.

```policy
/*
enum Role {
    Owner,
    Admin,
    Operator,
    Satellite,
}
*/

// Reports whether `role` is valid.
function is_valid_role(role string) bool {
    let ok = role == "Role_Owner" ||
             role == "Role_Admin" ||
             role == "Role_Operator" ||
             role == "Role_Satellite"
    return ok
}

// A device on the team.
//
// `role` must be one of:
// - "Role_Owner"
// - "Role_Admin"
// - "Role_Operator"
// - "Role_Satellite"
// This can be checked with `is_valid_role`.
fact Device[device_id id]=>{role string, sign_pk_id id, enc_pk_id id}

// A device's public IdentityKey.
//
// NB: `key_id` is also the DeviceId.
fact DeviceIdentKey[key_id id]=>{key bytes}

// A device's public SigningKey.
fact DeviceSignKey[key_id id]=>{device_id id, key bytes}

// A device's public EncryptionKey.
fact DeviceEncKey[key_id id]=>{device_id id, key bytes}

// Adds the device to the Control Plane.
finish function add_new_device(device struct NewDevice) {
    create Device[device_id: device.device_id]=>{role: device.role, sign_key_id: device.sign_pk_id, enc_key_id: device.enc_pk_id}
    create DeviceIdentKey[key_id: device.device_id]=>{key: device.ident_pk}
    create DeviceSignKey[key_id: device.sign_pk_id]=>{device_id: device.device_id, key: device.sign_pk}
    create DeviceEncKey[key_id: device.enc_pk_id]=>{device_id: device.device_id, key: device.enc_pk}
}

// The argument to `add_new_device`.
struct NewDevice {
    device_id id,
    sign_pk_id id,
    sign_pk bytes,
    enc_pk_id id,
    enc_pk bytes,
    role string,
}

// A device in the TT&C team.
struct Device {
    device_id id,
    sign_pk_id id,
    enc_pk_id id,
    role string,
}

// Returns a device.
function get_device(device_id id) struct Device {
    let device_info = unwrap query Device[device_id: device_id]=>{role: ?, sign_pk_id: ?, enc_pk_id: ?}
    let device = Device {
        device_id: device_id,
        sign_pk_id: device_info.sign_pk_id,
        enc_pk_id: device_info.enc_pk_id,
        role: device_info.role,
    }
    return device
}

// Reports whether the device is a Owner.
function is_owner(device_id id) bool {
    return has_role(device_id, "Role_Owner")
}

// Reports whether the device is a Admin.
function is_admin(device_id id) bool {
    return has_role(device_id, "Role_Admin")
}

// Reports whether the device is a Operator.
function is_operator(device_id id) bool {
    return has_role(device_id, "Role_Operator")
}

// Reports whether the device is a satellite.
function is_satellite(device_id id) bool {
    return has_role(device_id, "Role_Satellite")
}

// Reports whether the device's role is `role`.
function has_role(device_id id, role string) bool {
    let ok = exists Device[device_id: device_id]=>{role: role, sign_pk_id: ?, enc_pk_id: ?}
    return ok
}

// Reports whether `device_id` matches the DeviceId derived from
// `ident_pk`. (The IdentityKey's ID is the DeviceId.)
function ident_pk_matches_device_id(device_id id, ident_pk bytes) bool {
    let got_device_id = crypto_derive_key_id(ident_pk)
    return got_device_id == device_id
}

// Sanity checks the device per the stated invariants.
function is_valid_device(device struct Device) bool {
    // Must have an IdentityKey
    let has_ident_key = exists DeviceIdentKey[device_id: device.device_id]=>{key: ?}

    // Must have a SigningKey
    let has_sign_key = exists DeviceSignKey[device_id: device.device_id]=>{key: ?}

    // Must have an EncryptionKey
    let has_enc_key = exists DeviceEncKey[device_id: device.device_id]=>{key: ?}

    // Must have a valid role.
    let has_valid_role = is_valid_role(device.role)

    let valid = has_ident_key &&
                has_sign_key &&
                has_enc_key &&
                has_valid_role
    return is_valid
}
```

## CreateTtcTeam

The `CreateTtcTeam` command is the initial command in the
graph. It creates a Control Plane and establishes the author as
the initial owner of the Control Plane.

```policy
// Creates the TT&C Team.
action create_ttc_team(
    ttc_team_name string,
    device_name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = CreateTtcTeam {
        ctrl_plane_name: ctrl_plane_name,
        data_plane_state: data_plane_state,
        device_name: device_name,
        ident_pk: ident_pk,
        sign_pk: sign_pk,
        enc_pk: enc_pk,
    }
    publish cmd
}

effect TtcTeamCreated {
    // The name of the TT&C Team.
    name string,
    // The DeviceId of the creator of the TT&C Team.
    owner_id id,
}

command CreateTtcTeam {
    fields {
        // The name of this TT&C Team.
        ttc_team_name string,
        // The initial owner's name.
        device_name string,
        // The initial owner's public IdentityKey.
        ident_pk bytes,
        // The initial owner's public SigningKey.
        sign_pk bytes,
        // The initial owner's public EncryptionKey.
        enc_pk bytes,
    }

    policy {
        let author = crypto_author_id(envelope)

        // TODO(eric): just have one batch IDAM function for all
        // of this.

        // Check that the author of the command is providing the
        // correct IdentityKey.
        check ident_pk_matches_device_id(author, this.ident_pk)

        let sign_pk_id = crypto_derive_key_id(this.sign_pk)
        let enc_pk_id = crypto_derive_key_id(this.enc_pk)

        let device = NewDevice {
            device_id: author,
            ident_pk: this.ident_pk,
            sign_pk_id: sign_pk_id,
            sign_pk: this.sign_pk,
            enc_pk_id: enc_pk_id,
            enc_pk: this.enc_pk,
            role: "Role_Owner",
        }

        finish {
            add_new_device(device)

            emit TtcTeamCreated {
                name: this.ttc_team_name,
                owner_id: author,
            }
        }
    }

    recall {
        // TODO
    }
}
```

## AddOwner, AddAdmin, AddOperator, AddSatellite

The `add_owner`, `add_admin`, `add_operator`, and `add_satellite`
actions add a Owner, Admin, Operator, or Satellite
instance, respectively, to the TT&C Team.

```policy
// Adds a Owner to the TT&C Team.
action add_owner(
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_device_cmd(device, name, ident_pk, sign_pk, enc_pk, "Role_Owner")
    publish cmd
}

// Adds a Admin to the TT&C Team.
action add_admin(
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_device_cmd(device, name, ident_pk, sign_pk, enc_pk, "Role_Admin")
    publish cmd
}

// Adds a Operator to the TT&C Team.
action add_operator(
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_device_cmd(device, name, ident_pk, sign_pk, enc_pk, "Role_Operator")
    publish cmd
}

// Adds a satellite to the TT&C Team.
action add_satellite(
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_device_cmd(device, name, ident_pk, sign_pk, enc_pk, "Role_Satellite")
    publish cmd
}

// Creates an `AddDevice` command.
function new_add_device_cmd(
    device_id id,
    name string,
    sign_pk bytes,
    ident_pk bytes,
    enc_pk bytes,
    role string,
) struct AddDevice {
    let cmd = AddDevice {
        device_id: device_id,
        name: name,
        ident_pk: ident_pk,
        sign_pk: sign_pk,
        enc_pk: enc_pk,
        role: role,
    }
    return cmd
}

// A Owner was added to the TT&C Team.
effect OwnerAdded {
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A Admin was added to the TT&C Team.
effect AdminAdded {
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A Operator was added to the TT&C Team.
effect OperatorAdded {
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A satellite was added to the Control Plane.
effect SatelliteAdded {
    device_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

command AddDevice {
    fields {
        // The new device's DeviceId.
        device_id id,
        // The new device's name.
        name string,
        // The new device's public IdentityKey.
        ident_pk bytes,
        // The new device's public SigningKey.
        sign_pk bytes,
        // The new device's public EncryptionKey.
        enc_pk bytes,
        // The role to assign the device.
        role string,
    }

    policy {
        let author = get_device(crypto_author_id(envelope))
        check is_valid_device(author) // DEBUG

        // NB: this is redundant since we match on `this.role`
        // below, but keep it until we have enum support.
        check is_valid_role(this.role)

        match this.role {
            "Role_Owner" => {
                // Only Owners can create other Owners.
                check author.role == "Role_Owner"

                let add_device_effect = OwnerAdded {
                    device_id: this.device_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Admin" => {
                // Only Owners can create Admins.
                check author.role == "Role_Owner"

                let add_device_effect = AdminAdded {
                    device_id: this.device_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Operator" => {
                // Only Admins can create Operators.
                check author.role == "Role_Admin"

                let add_device_effect = OperatorAdded {
                    device_id: this.device_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Satellite" => {
                // Only Admins can create satellites.
                check author.role == "Role_Admin"

                let add_device_effect = SatelliteAdded {
                    device_id: this.device_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            _ => {
                // Unreachable
                check false
            }
        }

        // TODO(eric): just have one batch IDAM function for all
        // of this.

        // Check that the author of the command is providing the
        // correct IdentityKey.
        check ident_pk_matches_device_id(this.device_id, this.ident_pk)

        let sign_pk_id = crypto_derive_key_id(this.sign_pk)
        let enc_pk_id = crypto_derive_key_id(this.enc_pk)

        let device = NewDevice {
            device_id: author,
            sign_pk_id: sign_pk_id,
            sign_pk: this.sign_pk,
            enc_pk_id: enc_pk_id,
            enc_pk: this.enc_pk,
            role: this.role,
        }

        finish {
            add_new_device(device)
            emit add_device_effect
        }
    }

    recall {
        // TODO
    }
}
```

**Invariants:**

- Owners can only be added by Owners or through the
  initial [`CreateTtcTeam`](#createttcteam) command.
- Admins can only be added by Owners.
- Operators can only be added by Admins.
- Satellites can only be added by Admins.

## RemoveOwner, RemoveAdmin, RemoveOperator, RemoveSatellite

The `remove_owner`, `remove_admin`, `remove_operator`, and
`remove_satellite` actions permanently and irrevocably remove
a Owner, Admin, Operator, or satellite instance,
respectively, from the TT&C Team.

```policy
// Removes a Owner from the TT&C Team.
action remove_owner(device_id id) {
    let cmd = new_remove_device_cmd(device)
    publish cmd
}

// Removes a Admin from the TT&C Team.
action remove_admin(device_id id) {
    let cmd = new_remove_device_cmd(device)
    publish cmd
}

// Removes a Operator from the TT&C Team.
action remove_operator(device_id id) {
    let cmd = new_remove_device_cmd(device)
    publish cmd
}

// Removes a satellite from the TT&C Team.
action remove_satellite(device_id id) {
    let cmd = new_remove_device_cmd(device)
    publish cmd
}

// Creates a `RemoveDevice` command.
function new_remove_device_cmd(device_id id) struct RemoveDevice {
    let cmd = RemoveDevice {
        device_id: device,
    }
    return cmd
}

// A Owner was removed from the TT&C Team.
effect OwnerRemoved {
    device_id id,
}

// A Admin was removed from the TT&C Team.
effect AdminRemoved  {
    device_id id,
}

// A Operator was removed form the TT&C Team.
effect OperatorRemoved {
    device_id id,
}

// A satellite was removed from the TT&C Team.
effect SatelliteRemoved {
    device_id id,
}

// Deletes a device.
finish function remove_device(device struct Device) {
    delete Device[device_id: device.device_id]
    delete DeviceIdentKey[key_id: device.device_id]
    delete DeviceSignKey[key_id: device.sign_pk_id]
    delete DeviceEncKey[key_id: device.enc_key_id]
}

command RemoveDevice {
    fields {
        // The DeviceId of the device being removed.
        device_id id,
    }

    policy {
        let author = get_device(crypto_author_id(envelope))
        check is_valid_device(author) // DEBUG

        let device = get_device(this.device_id)
        check is_valid_device(this.device_id) // DEBUG

        match device.role {
            "Role_Owner" => {
                // Owners cannot remove *other* Owners,
                // but they can remove themselves.
                check author.role == "Role_Owner" &&
                      author.device_id == this.device_id

                // But there must always be at least one owner.
                // check at_least 2 Device[device_id: ?]=>{role: "Role_Owner", sign_key_id: ?, enc_key_id: ?}

                finish {
                    remove_device(device)
                    emit OwnerRemoved {
                        device_id: this.device_id,
                    }
                }
            }
            "Role_Admin" => {
                // Only Owners can remove Admins.
                check author.role == "Role_Owner"

                finish {
                    remove_device(device)
                    emit AdminRemoved {
                        device_id: this.device_id,
                    }
                }
            }
            "Role_Operator" => {
                // Only Owners or Admins can remove
                // Operators.
                check author.role == "Role_Owner" ||
                      author.role == "Role_Admin"

                finish {
                    remove_device(device)
                    emit OperatorRemoved {
                        device_id: this.device_id,
                    }
                }
            }
            "Role_Satellite" => {
                // Only Owners or Admins can remove
                // remove satellites.
                check author.role == "Role_Owner" ||
                      author.role == "Role_Admin"

                finish {
                    remove_device(device)
                    emit SatelliteRemoved {
                        device_id: this.device_id,
                    }
                }
            }
        }
    }

    recall {
        finish {
            afc_remove_all_channels(this.device_id)
        }
    }
}
```

**Invariants:**

- Devices cannot remove themselves.
- There must always be at least one Owner.
- Owners can only be removed by other Owners.
- Admins can only be removed by other Admins or the
  Owner.
- Operators can only be removed by Admins or the
  Owner.
- Satellites can only be removed by Admins or Owners

## CreateAfcLabel

```policy
// Reports whether `v` is an unsigned, 32-bit integer.
function is_u32(v int) bool {
    return v >= 0 && v <= 4294967295
}

// Reports whether `label` has the valid format for an AFC label.
function is_valid_afc_label(label int) bool {
    return is_u32(v)
}

// Creates an AFC label.
action create_afc_label(name string, label int) {
    let cmd = CreateAfcLabel {
        name: name,
        label: label,
    }
    publish cmd
}

// Records that an AFC label exists.
fact AfcLabel[label int]=>{name string}

effect AfcLabelCreated {
    name string,
    label int,
}

command CreateAfcLabel {
    fields {
        // A textual name for the label.
        name string,
        // The label being added.
        label int,
    }

    policy {
        let author = crypto_author_id(envelope)
        check is_valid_device(get_device(author)) // DEBUG

        // Only Admins can create AFC labels.
        check is_admin(author)

        // It must be a valid AFC label.
        check is_valid_afc_label(this.label)

        finish {
            create AfcLabel[label: this.label]=>{name: this.name}

            emit AfcLabelCreated {
                name: this.name,
                label: this.label,
            }
        }
    }

    recall {
        // TODO
    }
}
```

- Only Admins are allowed to create AFC labels.

## AssignAfcLabel

```policy
/*
// Describes what channel operations a device is permitted to use
// for a particular label.
enum ChanOp {
    // Can only encrypt.
    SealOnly,
    // Can only decrypt.
    OpenOnly,
    // Can encrypt and decrypt.
    Bidirectional,
}
*/

// Reports whether `op` is valid.
function is_valid_chan_op(op string) bool {
    let ok = op == "ChanOp_SealOnly" ||
             op == "ChanOp_OpenOnly" ||
             op == "ChanOp_Bidirectional"
    return ok
}

// Assigns the device the AFC `label`.
action assign_afc_label(device_id id, label int, op string) {
    let cmd = AssignAfcLabel {
        device_id: device_id,
        label: label,
        op: op,
    }
    publish cmd
}

effect AfcLabelAssigned {
    // The device being assigned the label.
    device_id id,
    // The name of the label being assigned.
    name string,
    // The label being assigned.
    label int,
    // The operations that can be performed with the label.
    op string,
}

// Records that a device is allowed to use an AFC label.
fact AssignedAfcLabel[device_id id, label int]=>{op string}

// Reports whether the devices have permission to create
// a bidirectional channel with each other.
function can_create_bidi_channel(device1 id, device2 id, label int) bool {
    let device1_ok = exists AssignedAfcLabel[device_id: device1, label: label]=>{op: "ChanOp_Bidirectional"}
    let device2_ok = exists AssignedAfcLabel[device_id: device2, label: label]=>{op: "ChanOp_Bidirectional"}
    return device1_ok && device2_ok
}

// Reports whether the devices have permission to create
// a unidirectional channel with each other.
function can_create_uni_channel(send_id id, open_id id, label int) bool {
    let send_op = get_allowed_op(send_id, label)
    let open_op = get_allowed_op(open_id, label)

    // TODO(eric): maybe we should allow complex match
    // expressions?
    let ok = (send_op == "ChanOp_SendOnly" && recv_op == "ChanOp_OpenOnly") ||
             (send_op == "ChanOp_SendOnly" && recv_op == "ChanOp_Bidirectional") ||
             (send_op == "ChanOp_Bidirectional" && recv_op == "ChanOp_OnlyOnly") ||
             (send_op == "ChanOp_Bidirectional" && recv_op == "ChanOp_Bidirectional")
    return ok
}

// Returns the channel operation for a particular label.
function get_allowed_op(device_id id, label int) string {
    let device_info = unwrap query AssignedAfcLabel[device_id: device_id, label: label]=>{op: ?}
    return device_info.op
}

command AssignAfcLabel {
    fields {
        // The device being assigned the label.
        device_id id,
        // The label being assigned.
        label int,
        // The operations that can be performed with the label.
        op string,
    }

    policy {
        let author = get_device(crypto_author_id(envelope))
        check is_valid_device(author) // DEBUG

        // Only Admins are allowed to assign AFC
        // labels.
        check is_admin(author)

        // Obviously it must be a valid label.
        check is_valid_afc_label(this.label)

        // Obviously it must be a valid channel op.
        check is_valid_chan_op(this.op)

        // The label must exist.
        let label = unwrap query AfcLabel[label: this.label]=>{name: ?}

        finish {
            create AssignedAfcLabel[device_id: this.device_id, label: this.label]=>{op: this.op}

            emit AfcLabelAssigned {
                device_id: this.device_id,
                name: label.name,
                label: this.label,
                op: this.op,
            }
        }
    }

    recall {
        // TODO
    }
}
```

**Invariants**:

- Only Admins are allowed to assign AFC labels.

## RevokeAfcLabel

```policy
// Revokes the device's access to the AFC `label`.
action revoke_afc_label(device_id id, label int) {
    let cmd = RevokeAfcLabel {
        device_id: device_id,
        label: label,
    }
    publish cmd
}

effect AfcLabelRevoked {
    // The device for whom the label is being revoked.
    device_id id,
    // The label being revoked.
    label int,
}

command RevokeAfcLabel {
    fields {
        // The device for whom the label is being revoked.
        device_id id,
        // The label being revoked.
        label int,
    }

    policy {
        let author = get_device(crypto_author_id(envelope))
        check is_valid_device(author) // DEBUG

        // Only Owners or Admins are allowed to revoke
        // AFC labels.
        check author.role == "Role_Owner" ||
              author.role == "Role_Admin"

        // Obviously it must be a valid label.
        check is_valid_afc_label(this.label)

        finish {
            delete AssignedAfcLabel[device_id: this.device_id, label: this.label]

            emit AfcLabelRevoked {
                device_id: this.device_id,
                label: this.label,
            }
        }
    }

    recall {
        finish {
            afc_remove_channel(this.device_id, this.label)
        }
    }
}
```

**Invariants**:

- Only Owners and Admins are allowed to revoke AFC
  labels.

## CreateAfcBidiChannel

Creates a bidirectional AFC channel.

```policy
action create_afc_bidi_channel(peer_id id, label int) {
}

// Records that a bidirectional AFC channel has been created.
fact AfcBidiChannel[device1 id, device2 id, label int]=>{}

effect AfcBidiChannelCreated {
    device1 id,
    device2 id,
    label int,
}

command CreateAfcBidiChannel {
    fields {
        peer id,
        label int,
        encap bytes,
    }

    policy {
        let author = crypto_author_id(envelope)
        check is_valid_device(get_device(author)) // DEBUG

        let peer = get_device(this.peer_id)
        check is_valid_device(peer) // DEBUG

        // Devices can't create channels with themselves.
        check this.peer != author

        // Both devices must have bidirectional permissions.
        check can_create_bidi_channel(author.device_id, peer.device_id, this.label)

        // It must be a valid label.
        check is_valid_afc_label(this.label)

        let our_id = device_current_device_id()

        // Are we the intended recipient of this command?
        match this.peer == our_id {
            true => {
                let parent_cmd_id = braid_head_id()
                let author_enc_pk = get_enc_key(peer)
                finish {
                    create AfcBidiChannel[
                        device1: author.device_id,
                        device2: peer.device_id,
                        label: this.label,
                    ]=>{encap: encap}

                    // We're creating a new channel, so get rid
                    // of the existing channel, if any.
                    afc_remove_channel(author.device_id, None)
                    afc_store_bidi_keys_responder(
                        parent_cmd_id,
                        our_sk_id,
                        our_id,
                        author.device_id,
                        author_enc_pk,
                        label,
                        this.encap,
                    )

                    emit AfcBidiChannelCreated {
                        device1: author,
                        device2: peer,
                    }
                }
            }
            false => {
                finish {
                    create AfcBidiChannel[
                        device1: author.device_id,
                        device2: peer.device_id,
                        label: this.label,
                    ]=>{encap: encap}

                    emit AfcBidiChannelCreated {
                        device1: author.device_id,
                        device2: peer.device_id,
                    }
                }
            }
        }
    }

    recall {
        finish {
            afc_remove_channel(this.peer_id, this.label)
        }
    }
}
```

**Invariants**:

- Satellites and Operators can only create channels for
  the labels they've been assigned.
- Satellites and Operators can only create bidi channels
  for their labels that have `ChanOp_Bidirectational`
  permission.

## CreateAfcUniChannel

```policy
action create_afc_uni_channel(seal_id id, open_id id, label int) {
    let parent_cmd_id = braid_head_id()
    let ch = afc_create_uni_channel(
        parent_cmd_id,
        our_sk_id,
        peer_pk,
        seal_id,
        open_id,
        label,
    )
    let cmd = CreateAfcUniChannel {
        seal_id: seal_id,
        open_id: open_id,
        label: label,
        encap: ch.encap,
    }
    publish cmd

    // At this point, the command was successfully added to the
    // graph.
    //
    // We now need to do two things:
    //   1. Remove the existing channel (if any) that we have
    //      with the peer.
    //   2. Store the new key.
    let our_id = device_current_device_id()
    match our_id == seal_id {
        // We're the seal-only side.
        true => {
            // afc_remove_channel(open_id, None)
            // afc_store_seal_only_key_initiator(open_id, label, ch.key)
        }
        // We're the open-only side.
        false => {
            // afc_remove_channel(seal_id, None)
            // afc_store_open_only_key_initiator(seal_id, label, ch.key)
        }
    }
}

// Records that a unidirectional AFC channel has been created.
fact AfcUniChannel[seal_id id, open_id id, label int]=>{}

command CreateAfcUniChannel {
    fields {
        // The DeviceId of the side that can encrypt data.
        seal_id id,
        // The DeviceId of the side that can decrypt data.
        open_id id,
        // The label to use.
        label int,
    }

    policy {
        let author = get_device(crypto_author_id(envelope))
        check is_valid_device(author) // DEBUG

        // The author must be half the channel.
        check author.device_id == this.seal_id ||
              author.device_id == this.open_id

        // Devices can't create channels with themselves.
        check this.seal_id != this.open_id

        check is_valid_device(get_device(this.seal_id)) // DEBUG
        check is_valid_device(get_device(this.open_id)) // DEBUG

        // Both devices must have valid permissions.
        check can_create_uni_channel(this.seal_id, this.open_id, this.label)

        // It must be a valid label.
        check is_valid_afc_label(this.label)

        // There are three mutually exclusive states:
        //
        //  1. We are the author of the command.
        //  2. We are the intended recipient of the command.
        //  3. We are not a channel participant and are simply
        //     observing this command.
        //
        // If this is state (1), then we've already stored the
        // channel key and only need to update the fact database.
        //
        // If this is state (2), then we need to decapsulate the
        // channel key and store it, as well as update the fact
        // database.
        //
        // If this is state (3), then we're not a participant in
        // this channel, so we only need to update the fact
        // database.
        let our_id = device_current_device_id()
        // Are we the author?
        let is_state_1 = our_id == author.device_id
        // Are we the intended participant?
        let is_state_2 = this.seal_id == our_id ||
                         this.open_id == our_id
        // Are we simply an observant?
        let is_state_3 = !is_state_1 && !is_state_2
        match is_state_2 {
            // Yep, this is state (2).
            true => {
                // Not state (1).
                check our_id != author.device_id // DEBUG
                // Not state (3).
                check this.seal_id == our_id ||
                      this.open_id == our_id // DEBUG

                let parent_cmd_id = braid_head_id()
                finish {
                    create AfcUniChannel[
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        label: this.label,
                    ]=>{encap: encap}
                    afc_store_open_only_key(
                        parent_cmd_id,
                        this.seal_id,
                        this.open_id,
                        this.label,
                        this.encap,
                    )
                    emit AfcUniChannelCreated {
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        encap: encap,
                    }
                }
            }
            // Nope, this is state (1) or (3).
            false => {
                // Nothing special to do here.
                finish {
                    create AfcUniChannel[
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        label: this.label,
                    ]=>{encap: encap}
                    emit AfcUniChannelCreated {
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        encap: encap,
                    }
                }
            }
        }
    }

    recall {
        finish {
            afc_remove_channel(this.peer, this.label)
        }
    }
}
```

**Invariants**:

- Satellites and Operators can only create channels for
  the labels they've been assigned.
- Satellites and Operators can only create unidirectional
  channels when the seal side has either `ChanOp_Bidirectional`
or `ChanOp_SealOnly` permissions for the label and the open side
has either `ChanOp_Bidirectional` or `ChanOp_OpenOnly`
permissions for the label.

# AFC FFI Policy

[AFC FFI Policy](ffi.md).
