pub mod tictactoe {
    policy_ifgen_macro::interface!("tests/data/tictactoe.md");

    pub fn doit(a: &mut impl Actor) -> Result<(), runtime::ClientError> {
        let id = policy_vm::Id::default();
        a.MakeMove(id, 1, 2)
    }
}

pub mod ttc {
    policy_ifgen_macro::interface!("tests/data/ttc.md");

    pub fn doit(a: &mut impl Actor) -> Result<(), runtime::ClientError> {
        let name = String::from("foobar");
        a.create_aps_label(name, 42)
    }
}
