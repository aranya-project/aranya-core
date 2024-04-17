---
policy-version: 3
---

# TT&C Policy

## Setup

```
use braid
use crypto
use device
```

## Users and Roles

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
- Revoke APS labels from Operators
- Revoke APS labels from Satellites

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

- Create APS channels with individual satellites as specified by
  Admins.

### Satellite

Satellites are individual satellites. They are only allowed to:

- Create APS channels with Operators as specified by
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

// A user on the team.
//
// `role` must be one of:
// - "Role_Owner"
// - "Role_Admin"
// - "Role_Operator"
// - "Role_Satellite"
// This can be checked with `is_valid_role`.
fact User[user_id id]=>{role string, sign_pk_id id, enc_pk_id id}

// A user's public IdentityKey.
//
// NB: `key_id` is also the UserID.
fact UserIdentKey[key_id id]=>{key bytes}

// A user's public SigningKey.
fact UserSignKey[key_id id]=>{user_id id, key bytes}

// A user's public EncryptionKey.
fact UserEncKey[key_id id]=>{user_id id, key bytes}

// Adds the user to the Control Plane.
finish function add_new_user(user struct NewUser) {
    create User[user_id: user.user_id]=>{role: user.role, sign_key_id: user.sign_pk_id, enc_key_id: user.enc_pk_id}
    create UserIdentKey[key_id: user.user_id]=>{key: user.ident_pk}
    create UserSignKey[key_id: user.sign_pk_id]=>{user_id: user.user_id, key: user.sign_pk}
    create UserEncKey[key_id: user.enc_pk_id]=>{user_id: user.user_id, key: user.enc_pk}
}

// The argument to `add_new_user`.
struct NewUser {
    user_id id,
    sign_pk_id id,
    sign_pk bytes,
    enc_pk_id id,
    enc_pk bytes,
    role string,
}

// A user in the TT&C team.
struct User {
    user_id id,
    sign_pk_id id,
    enc_pk_id id,
    role string,
}

// Returns a user.
function get_user(user_id id) struct User {
    let fact = unwrap query User[user_id: user_id]=>{role: ?, sign_pk_id: ?, enc_pk_id: ?}
    let user = User {
        user_id: user_id,
        sign_pk_id: fact.sign_pk_id,
        enc_pk_id: fact.enc_pk_id,
        role: fact.role,
    }
    return user
}

// Reports whether the user is a Owner.
function is_owner(user_id id) bool {
    return has_role(user_id, "Role_Owner")
}

// Reports whether the user is a Admin.
function is_admin(user_id id) bool {
    return has_role(user_id, "Role_Admin")
}

// Reports whether the user is a Operator.
function is_operator(user_id id) bool {
    return has_role(user_id, "Role_Operator")
}

// Reports whether the user is a satellite.
function is_satellite(user_id id) bool {
    return has_role(user_id, "Role_Satellite")
}

// Reports whether the user's role is `role`.
function has_role(user_id id, role string) bool {
    let ok = exists User[user_id: user_id]=>{role: role, sign_pk_id: ?, enc_pk_id: ?}
    return ok
}

// Reports whether `user_id` matches the UserID derived from
// `ident_pk`. (The IdentityKey's ID is the UserID.)
function ident_pk_matches_user_id(user_id id, ident_pk bytes) bool {
    let got_user_id = crypto_derive_key_id(ident_pk)
    return got_user_id == user_id
}

// Sanity checks the user per the stated invariants.
function is_valid_user(user struct User) bool {
    // Must have an IdentityKey
    let has_ident_key = exists UserIdentKey[user_id: user.user_id]=>{key: ?}

    // Must have a SigningKey
    let has_sign_key = exists UserSignKey[user_id: user.user_id]=>{key: ?}

    // Must have an EncryptionKey
    let has_enc_key = exists UserEncKey[user_id: user.user_id]=>{key: ?}

    // Must have a valid role.
    let has_valid_role = is_valid_role(user.role)

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
    user_name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = CreateTtcTeam {
        ctrl_plane_name: ctrl_plane_name,
        data_plane_state: data_plane_state,
        user_name: user_name,
        ident_pk: ident_pk,
        sign_pk: sign_pk,
        enc_pk: enc_pk,
    }
    publish cmd
}

effect TtcTeamCreated {
    // The name of the TT&C Team.
    name string,
    // The UserID of the creator of the TT&C Team.
    owner_id id,
}

command CreateTtcTeam {
    fields {
        // The name of this TT&C Team.
        ttc_team_name string,
        // The initial owner's name.
        user_name string,
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
        check ident_pk_matches_user_id(author, this.ident_pk)

        let sign_pk_id = crypto_derive_key_id(this.sign_pk)
        let enc_pk_id = crypto_derive_key_id(this.enc_pk)

        let user = NewUser {
            user_id: author,
            ident_pk: this.ident_pk,
            sign_pk_id: sign_pk_id,
            sign_pk: this.sign_pk,
            enc_pk_id: enc_pk_id,
            enc_pk: this.enc_pk,
            role: "Role_Owner",
        }

        finish {
            add_new_user(user)

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
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_user_cmd(user, name, ident_pk, sign_pk, enc_pk, "Role_Owner")
    publish cmd
}

// Adds a Admin to the TT&C Team.
action add_admin(
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_user_cmd(user, name, ident_pk, sign_pk, enc_pk, "Role_Admin")
    publish cmd
}

// Adds a Operator to the TT&C Team.
action add_operator(
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_user_cmd(user, name, ident_pk, sign_pk, enc_pk, "Role_Operator")
    publish cmd
}

// Adds a satellite to the TT&C Team.
action add_satellite(
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
) {
    let cmd = new_add_user_cmd(user, name, ident_pk, sign_pk, enc_pk, "Role_Satellite")
    publish cmd
}

// Creates an `AddUser` command.
function new_add_user_cmd(
    user_id id,
    name string,
    sign_pk bytes,
    ident_pk bytes,
    enc_pk bytes,
    role string,
) struct AddUser {
    let cmd = AddUser {
        user_id: user_id,
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
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A Admin was added to the TT&C Team.
effect AdminAdded {
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A Operator was added to the TT&C Team.
effect OperatorAdded {
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

// A satellite was added to the Control Plane.
effect SatelliteAdded {
    user_id id,
    name string,
    ident_pk bytes,
    sign_pk bytes,
    enc_pk bytes,
}

command AddUser {
    fields {
        // The new user's UserID.
        user_id id,
        // The new user's name.
        name string,
        // The new user's public IdentityKey.
        ident_pk bytes,
        // The new user's public SigningKey.
        sign_pk bytes,
        // The new user's public EncryptionKey.
        enc_pk bytes,
        // The role to assign the user.
        role string,
    }

    policy {
        let author = get_user(crypto_author_id(envelope))
        check is_valid_user(author) // DEBUG

        // NB: this is redundant since we match on `this.role`
        // below, but keep it until we have enum support.
        check is_valid_role(this.role)

        match this.role {
            "Role_Owner" => {
                // Only Owners can create other Owners.
                check author.role == "Role_Owner"

                let add_user_effect = OwnerAdded {
                    user_id: this.user_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Admin" => {
                // Only Owners can create Admins.
                check author.role == "Role_Owner"

                let add_user_effect = AdminAdded {
                    user_id: this.user_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Operator" => {
                // Only Admins can create Operators.
                check author.role == "Role_Admin"

                let add_user_effect = OperatorAdded {
                    user_id: this.user_id,
                    name: this.name,
                    ident_pk: this.ident_pk,
                    sign_pk: this.sign_pk,
                    enc_pk: this.enc_pk,
                }
            }
            "Role_Satellite" => {
                // Only Admins can create satellites.
                check author.role == "Role_Admin"

                let add_user_effect = SatelliteAdded {
                    user_id: this.user_id,
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
        check ident_pk_matches_user_id(this.user_id, this.ident_pk)

        let sign_pk_id = crypto_derive_key_id(this.sign_pk)
        let enc_pk_id = crypto_derive_key_id(this.enc_pk)

        let user = NewUser {
            user_id: author,
            sign_pk_id: sign_pk_id,
            sign_pk: this.sign_pk,
            enc_pk_id: enc_pk_id,
            enc_pk: this.enc_pk,
            role: this.role,
        }

        finish {
            add_new_user(user)
            emit add_user_effect
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
action remove_owner(user_id id) {
    let cmd = new_remove_user_cmd(user)
    publish cmd
}

// Removes a Admin from the TT&C Team.
action remove_admin(user_id id) {
    let cmd = new_remove_user_cmd(user)
    publish cmd
}

// Removes a Operator from the TT&C Team.
action remove_operator(user_id id) {
    let cmd = new_remove_user_cmd(user)
    publish cmd
}

// Removes a satellite from the TT&C Team.
action remove_satellite(user_id id) {
    let cmd = new_remove_user_cmd(user)
    publish cmd
}

// Creates a `RemoveUser` command.
function new_remove_user_cmd(user_id id) struct RemoveUser {
    let cmd = RemoveUser {
        user_id: user,
    }
    return cmd
}

// A Owner was removed from the TT&C Team.
effect OwnerRemoved {
    user_id id,
}

// A Admin was removed from the TT&C Team.
effect AdminRemoved  {
    user_id id,
}

// A Operator was removed form the TT&C Team.
effect OperatorRemoved {
    user_id id,
}

// A satellite was removed from the TT&C Team.
effect SatelliteRemoved {
    user_id id,
}

// Deletes a user.
finish function remove_user(user struct User) {
    delete User[user_id: user.user_id]
    delete UserIdentKey[key_id: user.user_id]
    delete UserSignKey[key_id: user.sign_pk_id]
    delete UserEncKey[key_id: user.enc_key_id]
}

command RemoveUser {
    fields {
        // The UserID of the user being removed.
        user_id id,
    }

    policy {
        let author = get_user(crypto_author_id(envelope))
        check is_valid_user(author) // DEBUG

        let user = get_user(this.user_id)
        check is_valid_user(this.user_id) // DEBUG

        match user.role {
            "Role_Owner" => {
                // Owners cannot remove *other* Owners,
                // but they can remove themselves.
                check author.role == "Role_Owner" &&
                      author.user_id == this.user_id

                // But there must always be at least one owner.
                // check at_least 2 User[user_id: ?]=>{role: "Role_Owner", sign_key_id: ?, enc_key_id: ?}

                finish {
                    remove_user(user)
                    emit OwnerRemoved {
                        user_id: this.user_id,
                    }
                }
            }
            "Role_Admin" => {
                // Only Owners can remove Admins.
                check author.role == "Role_Owner"

                finish {
                    remove_user(user)
                    emit AdminRemoved {
                        user_id: this.user_id,
                    }
                }
            }
            "Role_Operator" => {
                // Only Owners or Admins can remove
                // Operators.
                check author.role == "Role_Owner" ||
                      author.role == "Role_Admin"

                finish {
                    remove_user(user)
                    emit OperatorRemoved {
                        user_id: this.user_id,
                    }
                }
            }
            "Role_Satellite" => {
                // Only Owners or Admins can remove
                // remove satellites.
                check author.role == "Role_Owner" ||
                      author.role == "Role_Admin"

                finish {
                    remove_user(user)
                    emit SatelliteRemoved {
                        user_id: this.user_id,
                    }
                }
            }
        }
    }

    recall {
        finish {
            aps_remove_all_channels(this.user_id)
        }
    }
}
```

**Invariants:**

- Users cannot remove themselves.
- There must always be at least one Owner.
- Owners can only be removed by other Owners.
- Admins can only be removed by other Admins or the
  Owner.
- Operators can only be removed by Admins or the
  Owner.
- Satellites can only be removed by Admins or Owners

## CreateApsLabel

```policy
// Reports whether `v` is an unsigned, 32-bit integer.
function is_u32(v int) bool {
    return v >= 0 && v <= 4294967295
}

// Reports whether `label` has the valid format for an APS label.
function is_valid_aps_label(label int) bool {
    return is_u32(v)
}

// Creates an APS label.
action create_aps_label(name string, label int) {
    let cmd = CreateApsLabel {
        name: name,
        label: label,
    }
    publish cmd
}

// Records that an APS label exists.
fact ApsLabel[label int]=>{name string}

effect ApsLabelCreated {
    name string,
    label int,
}

command CreateApsLabel {
    fields {
        // A textual name for the label.
        name string,
        // The label being added.
        label int,
    }

    policy {
        let author = crypto_author_id(envelope)
        check is_valid_user(get_user(author)) // DEBUG

        // Only Admins can create APS labels.
        check is_admin(author)

        // It must be a valid APS label.
        check is_valid_aps_label(this.label)

        finish {
            create ApsLabel[label: this.label]=>{name: this.name}

            emit ApsLabelCreated {
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

- Only Admins are allowed to create APS labels.

## AssignApsLabel

```policy
/*
// Describes what channel operations a user is permitted to use
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

// Assigns the user the APS `label`.
action assign_aps_label(user_id id, label int, op string) {
    let cmd = AssignApsLabel {
        user_id: user_id,
        label: label,
        op: op,
    }
    publish cmd
}

effect ApsLabelAssigned {
    // The user being assigned the label.
    user_id id,
    // The name of the label being assigned.
    name string,
    // The label being assigned.
    label int,
    // The operations that can be performed with the label.
    op string,
}

// Records that a user is allowed to use an APS label.
fact AssignedApsLabel[user_id id, label int]=>{op string}

// Reports whether the users have permission to create
// a bidirectional channel with each other.
function can_create_bidi_channel(user1 id, user2 id, label int) bool {
    let user1_ok = exists AssignedApsLabel[user_id: user1, label: label]=>{op: "ChanOp_Bidirectional"}
    let user2_ok = exists AssignedApsLabel[user_id: user2, label: label]=>{op: "ChanOp_Bidirectional"}
    return user1_ok && user2_ok
}

// Reports whether the users have permission to create
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
function get_allowed_op(user_id id, label int) string {
    let fact = unwrap query AssignedApsLabel[user_id: user_id, label: label]=>{op: ?}
    return fact.op
}

command AssignApsLabel {
    fields {
        // The user being assigned the label.
        user_id id,
        // The label being assigned.
        label int,
        // The operations that can be performed with the label.
        op string,
    }

    policy {
        let author = get_user(crypto_author_id(envelope))
        check is_valid_user(author) // DEBUG

        // Only Admins are allowed to assign APS
        // labels.
        check is_admin(author)

        // Obviously it must be a valid label.
        check is_valid_aps_label(this.label)

        // Obviously it must be a valid channel op.
        check is_valid_chan_op(this.op)

        // The label must exist.
        let label = unwrap query ApsLabel[label: this.label]=>{name: ?}

        finish {
            create AssignedApsLabel[user_id: this.user_id, label: this.label]=>{op: this.op}

            emit ApsLabelAssigned {
                user_id: this.user_id,
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

- Only Admins are allowed to assign APS labels.

## RevokeApsLabel

```policy
// Revokes the user's access to the APS `label`.
action revoke_aps_label(user_id id, label int) {
    let cmd = RevokeApsLabel {
        user_id: user_id,
        label: label,
    }
    publish cmd
}

effect ApsLabelRevoked {
    // The user for whom the label is being revoked.
    user_id id,
    // The label being revoked.
    label int,
}

command RevokeApsLabel {
    fields {
        // The user for whom the label is being revoked.
        user_id id,
        // The label being revoked.
        label int,
    }

    policy {
        let author = get_user(crypto_author_id(envelope))
        check is_valid_user(author) // DEBUG

        // Only Owners or Admins are allowed to revoke
        // APS labels.
        check author.role == "Role_Owner" ||
              author.role == "Role_Admin"

        // Obviously it must be a valid label.
        check is_valid_aps_label(this.label)

        finish {
            delete AssignedApsLabel[user_id: this.user_id, label: this.label]

            emit ApsLabelRevoked {
                user_id: this.user_id,
                label: this.label,
            }
        }
    }

    recall {
        finish {
            aps_remove_channel(this.user_id, this.label)
        }
    }
}
```

**Invariants**:

- Only Owners and Admins are allowed to revoke APS
  labels.

## CreateApsBidiChannel

Creates a bidirectional APS channel.

```policy
action create_aps_bidi_channel(peer_id id, label int) {
}

// Records that a bidirectional APS channel has been created.
fact ApsBidiChannel[user1 id, user2 id, label int]=>{}

effect ApsBidiChannelCreated {
    user1 id,
    user2 id,
    label int,
}

command CreateApsBidiChannel {
    fields {
        peer id,
        label int,
        encap bytes,
    }

    policy {
        let author = crypto_author_id(envelope)
        check is_valid_user(get_user(author)) // DEBUG

        let peer = get_user(this.peer_id)
        check is_valid_user(peer) // DEBUG

        // Users can't create channels with themselves.
        check this.peer != author

        // Both users must have bidirectional permissions.
        check can_create_bidi_channel(author.user_id, peer.user_id, this.label)

        // It must be a valid label.
        check is_valid_aps_label(this.label)

        let our_id = device_current_user_id()

        // Are we the intended recipient of this command?
        match this.peer == our_id {
            true => {
                let parent_cmd_id = braid_head_id()
                let author_enc_pk = get_enc_key(peer)
                finish {
                    create ApsBidiChannel[
                        user1: author.user_id,
                        user2: peer.user_id,
                        label: this.label,
                    ]=>{encap: encap}

                    // We're creating a new channel, so get rid
                    // of the existing channel, if any.
                    aps_remove_channel(author.user_id, None)
                    aps_store_bidi_keys_responder(
                        parent_cmd_id,
                        our_sk_id,
                        our_id,
                        author.user_id,
                        author_enc_pk,
                        label,
                        this.encap,
                    )

                    emit ApsBidiChannelCreated {
                        user1: author,
                        user2: peer,
                    }
                }
            }
            false => {
                finish {
                    create ApsBidiChannel[
                        user1: author.user_id,
                        user2: peer.user_id,
                        label: this.label,
                    ]=>{encap: encap}

                    emit ApsBidiChannelCreated {
                        user1: author.user_id,
                        user2: peer.user_id,
                    }
                }
            }
        }
    }

    recall {
        finish {
            aps_remove_channel(this.peer_id, this.label)
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

## CreateApsUniChannel

```policy
action create_aps_uni_channel(seal_id id, open_id id, label int) {
    let parent_cmd_id = braid_head_id()
    let ch = aps_create_uni_channel(
        parent_cmd_id,
        our_sk_id,
        peer_pk,
        seal_id,
        open_id,
        label,
    )
    let cmd = CreateApsUniChannel {
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
    let our_id = device_current_user_id()
    match our_id == seal_id {
        // We're the seal-only side.
        true => {
            // aps_remove_channel(open_id, None)
            // aps_store_seal_only_key_initiator(open_id, label, ch.key)
        }
        // We're the open-only side.
        false => {
            // aps_remove_channel(seal_id, None)
            // aps_store_open_only_key_initiator(seal_id, label, ch.key)
        }
    }
}

// Records that a unidirectional APS channel has been created.
fact ApsUniChannel[seal_id id, open_id id, label int]=>{}

command CreateApsUniChannel {
    fields {
        // The UserID of the side that can encrypt data.
        seal_id id,
        // The UserID of the side that can decrypt data.
        open_id id,
        // The label to use.
        label int,
    }

    policy {
        let author = get_user(crypto_author_id(envelope))
        check is_valid_user(author) // DEBUG

        // The author must be half the channel.
        check author.user_id == this.seal_id ||
              author.user_id == this.open_id

        // Users can't create channels with themselves.
        check this.seal_id != this.open_id

        check is_valid_user(get_user(this.seal_id)) // DEBUG
        check is_valid_user(get_user(this.open_id)) // DEBUG

        // Both users must have valid permissions.
        check can_create_uni_channel(this.seal_id, this.open_id, this.label)

        // It must be a valid label.
        check is_valid_aps_label(this.label)

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
        let our_id = device_current_user_id()
        // Are we the author?
        let is_state_1 = our_id == author.user_id
        // Are we the intended participant?
        let is_state_2 = this.seal_id == our_id ||
                         this.open_id == our_id
        // Are we simply an observant?
        let is_state_3 = !is_state_1 && !is_state_2
        match is_state_2 {
            // Yep, this is state (2).
            true => {
                // Not state (1).
                check our_id != author.user_id // DEBUG
                // Not state (3).
                check this.seal_id == our_id ||
                      this.open_id == our_id // DEBUG

                let parent_cmd_id = braid_head_id()
                finish {
                    create ApsUniChannel[
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        label: this.label,
                    ]=>{encap: encap}
                    aps_store_open_only_key(
                        parent_cmd_id,
                        this.seal_id,
                        this.open_id,
                        this.label,
                        this.encap,
                    )
                    emit ApsUniChannelCreated {
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
                    create ApsUniChannel[
                        seal_id: this.seal_id,
                        open_id: this.open_id,
                        label: this.label,
                    ]=>{encap: encap}
                    emit ApsUniChannelCreated {
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
            aps_remove_channel(this.peer, this.label)
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

# APS FFI Policy

[APS FFI Policy](ffi.md).
