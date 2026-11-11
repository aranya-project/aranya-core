#![cfg(test)]

pub const TEST_POLICY_1: &str = r#"
effect Bar {
    x: int
}

command Foo with StubBase {
    fields {
        a: int,
        b: int,
    }
    policy {
        let sum = saturating_add(this.a, this.b)
        finish {
            emit Bar{x: sum}
        }
    }
}

action[null] foo(b: int) {
    let x = if b == 0 { :4 } else { :3 }
    let y = Foo{
        a: x,
        b: 4
    }
    publish y
}

action[null] bar() {
    action foo(0)
    action foo(1)
}
"#;

pub const TEST_POLICY_2: &str = r#"
fact Foo[]=>{x: int}

effect Update {
    value: int
}

command Set with StubBase {
    fields {
        a: int,
    }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x}
            emit Update{value: x}
        }
    }
}

command Clear with StubBase {
    fields {}
    policy {
        finish {
            delete Foo[]
        }
    }
}

command Increment with StubBase {
    fields {}
    policy {
        let r = query Foo[]=>{x: ?} or test_fail()
        let new_x = add(r.x, 1) or test_fail()
        finish {
            update Foo[]=>{x: r.x} to {x: new_x}
            emit Update{value: new_x}
        }
    }
}
"#;

pub const POLICY_TEST_UPDATE: &str = r#"
fact Foo[]=>{x: int}

command Set with StubBase {
    fields {
        a: int,
    }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x}
        }
    }
}

command Increment with StubBase {
    fields {}
    policy {
        let r = query Foo[]=>{x: ?} or test_fail()
        let new_x = add(r.x, 1) or test_fail()
        finish {
            update Foo[]=>{x: 0} to {x: new_x}
        }
    }
}
"#;

pub const POLICY_MATCH: &str = r#"
    command Result with StubBase {
        fields {
            x: int
        }
        policy {}
    }

    action[null] foo(x: int) {
        match x {
            5 => {
                publish Result { x }
            }
            6 => {
                publish Result { x }
            }
            _ => {
                publish Result { x: saturating_add(1, x) }
            }
        }
    }
"#;

pub const POLICY_IS: &str = r#"
    command Result with StubBase {
        fields {
            x: int
        }
        policy {}
    }
    command Empty with StubBase {
        fields { }
        policy {}
    }
    action[null] check_none(x: option[int]) {
        match x {
            None => { publish Empty { } }
            Some(y) => { publish Result { x: y } }
        }
    }
"#;
