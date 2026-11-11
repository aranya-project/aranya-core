use alloc::collections::BTreeMap;

use aranya_policy_vm::{CommandDef, ConstValue, Machine, ast::Identifier};

use super::error::AttributeError;
use crate::Priority;

#[derive(Copy, Clone, Debug, PartialEq)]
pub(super) enum VmPriority {
    Init,
    Basic(u32),
    Finalize,
    Ephemeral,
}

impl Default for VmPriority {
    fn default() -> Self {
        Self::Basic(0)
    }
}

impl From<VmPriority> for Priority {
    fn from(value: VmPriority) -> Self {
        match value {
            VmPriority::Init => Self::Init,
            VmPriority::Basic(p) => Self::Basic(p),
            VmPriority::Finalize => Self::Finalize,
            VmPriority::Ephemeral => Self::Basic(0), // ?
        }
    }
}

/// Scans command attributes for priorities and creates the priority map from them.
pub(super) fn get_command_priorities(
    machine: &Machine,
) -> Result<BTreeMap<Identifier, VmPriority>, AttributeError> {
    machine
        .command_defs
        .iter()
        .map(|def| {
            let priority = get_command_priority(def)?;
            Ok((def.name.clone(), priority))
        })
        .collect()
}

/// Get the priority for one command from flavor and attributes.
fn get_command_priority(def: &CommandDef) -> Result<VmPriority, AttributeError> {
    match def.flavor.as_str() {
        "basic" => Ok(VmPriority::Basic(load_priority(def)?)),
        // If not basic, it should not have priority attribute.
        flavor if def.attributes.iter().any(|a| a.name == "priority") => Err(
            AttributeError::should_not_have(flavor, def.name.as_str(), "priority"),
        ),
        "ephemeral" => Ok(VmPriority::Ephemeral),
        "init" => Ok(VmPriority::Init),
        "finalize" => Ok(VmPriority::Finalize),
        flavor => Err(AttributeError::unknown_flavor(flavor, def.name.as_str())),
    }
}

/// Read the priority attribute.
fn load_priority(def: &CommandDef) -> Result<u32, AttributeError> {
    let cmd_name = def.name.as_str();
    let attr_name = "priority";
    let attr = def
        .attributes
        .iter()
        .find(|a| a.name == attr_name)
        .ok_or_else(|| AttributeError::missing(cmd_name, attr_name))?;
    let ConstValue::Int(int) = attr.value else {
        return Err(AttributeError::type_mismatch(
            cmd_name,
            attr_name,
            "Int",
            &attr.value.type_name(),
        ));
    };
    u32::try_from(int).map_err(|_| {
        AttributeError::int_range(cmd_name, attr_name, u32::MIN.into(), u32::MAX.into())
    })
}

#[cfg(test)]
mod test {
    use alloc::format;

    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_str;
    use aranya_policy_vm::{ast::Version, ident};

    use super::*;
    use crate::vm_policy::FLAVORS;

    #[test]
    fn test_require_command_priority() {
        let cases = [
            r#"
            base[basic] Base { get_key { return None } }
            command Test with Base {
                fields {}
                policy {}
            }
            "#,
            r#"
            base[basic] Base { get_key { return None } }
            command Test with Base {
                attributes {}
                fields {}
                policy {}
            }
            "#,
            r#"
            base[basic] Base { get_key { return None } }
            command Test with Base {
                attributes {
                    init: false,
                    finalize: false,
                }
                fields {}
                policy {}
            }
            "#,
        ];

        for case in cases {
            let ast = parse_policy_str(case, Version::V2).unwrap();
            let module = Compiler::new(&ast).flavors(&FLAVORS).compile().unwrap();
            let machine = Machine::from_module(module).expect("can create machine");
            let def = machine.command_defs.get(&ident!("Test")).unwrap();
            let err = get_command_priority(def).expect_err("should fail");
            assert_eq!(err, AttributeError::missing("Test", "priority"));
        }
    }

    #[test]
    fn test_get_command_priority() {
        fn process(flavor: &str, attrs: &str) -> Result<VmPriority, AttributeError> {
            let policy = format!(
                r#"
                base[{flavor}] Base {{ get_key {{ return None }} }}
                command Test with Base {{
                    attributes {{
                        {attrs}
                    }}
                    fields {{ }}
                    policy {{ }}
                }}
                "#
            );
            let ast = parse_policy_str(&policy, Version::V2).unwrap();
            let module = Compiler::new(&ast).flavors(&FLAVORS).compile().unwrap();
            let machine = Machine::from_module(module).expect("can create machine");
            let def = machine.command_defs.get(&ident!("Test")).unwrap();
            get_command_priority(def)
        }

        assert_eq!(process("basic", "priority: 42"), Ok(VmPriority::Basic(42)));
        assert_eq!(
            process("basic", "finalize: false, priority: 42"),
            Ok(VmPriority::Basic(42))
        );
        assert_eq!(
            process("basic", "init: false, priority: 42, finalize: false"),
            Ok(VmPriority::Basic(42))
        );

        assert_eq!(process("init", ""), Ok(VmPriority::Init));
        assert_eq!(process("finalize", ""), Ok(VmPriority::Finalize));

        assert_eq!(
            process("basic", "priority: false"),
            Err(AttributeError::type_mismatch(
                "Test", "priority", "Int", "Bool"
            ))
        );
        assert_eq!(
            process("basic", "priority: -1"),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );
        assert_eq!(
            process("basic", &format!("priority: {}", i64::MAX)),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );

        assert_eq!(
            process("finalize", "priority: 42"),
            Err(AttributeError::should_not_have(
                "finalize", "Test", "priority"
            ))
        );
        assert_eq!(
            process("init", "priority: 42"),
            Err(AttributeError::should_not_have("init", "Test", "priority"))
        );
    }
}
