#![cfg(test)]

pub const TEST_POLICY_1: &str = r#"
effect Bar {
    x int
}

command Foo {
    fields {
        a int,
        b int,
    }
    seal { return todo() }
    open { return todo() }
    policy {
        let sum = this.a + this.b
        finish {
            emit Bar{x: sum}
        }
    }
}

action foo(b int) {
    let x = if b == 0 { :4 } else { :3 }
    let y = Foo{
        a: x,
        b: 4
    }
    publish y
}

action bar() {
    action foo(0)
    action foo(1)
}
"#;

pub const TEST_POLICY_2: &str = r#"
fact Foo[]=>{x int}

effect Update {
    value int
}

command Set {
    fields {
        a int,
    }
    seal { return todo() }
    open { return todo() }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x: x}
            emit Update{value: x}
        }
    }
}

command Clear {
    fields {}
    seal { return todo() }
    open { return todo() }
    policy {
        finish {
            delete Foo[]
        }
    }
}

command Increment {
    fields {}
    seal { return todo() }
    open { return todo() }
    policy {
        let r = unwrap query Foo[]=>{x: ?}
        let new_x = r.x + 1
        finish {
            update Foo[]=>{x: r.x} to {x: new_x}
            emit Update{value: new_x}
        }
    }
}
"#;

pub const POLICY_INVALID_UPDATE: &str = r#"
fact Foo[]=>{x int}

command Set {
    fields {
        a int,
    }
    seal { return todo() }
    open { return todo() }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x: x}
        }
    }
}

command Increment {
    fields {}
    seal { return todo() }
    open { return todo() }
    policy {
        let r = unwrap query Foo[]=>{x: ?}
        let new_x = r.x + 1
        finish {
            update Foo[]=>{x: 0} to {x: new_x}
        }
    }
}
"#;

pub const POLICY_MATCH: &str = r#"
    command Result {
        fields {
            x int
        }
        seal { return todo() }
        open { return todo() }
    }

    action foo(x int) {
        match x {
            5 => {
                publish Result { x: x }
            }
            6 => {
                publish Result { x: x }
            }
        }
    }
"#;

pub const POLICY_IS: &str = r#"
    command Result {
        fields {
            x int
        }
        seal { return todo() }
        open { return todo() }
    }
    command Empty {
        fields { }
        seal { return todo() }
        open { return todo() }
    }
    action check_none(x optional int) {
        if x is None {
            publish Empty { }
        }
        if x is Some {
            publish Result { x: unwrap x }
        }
    }
"#;
