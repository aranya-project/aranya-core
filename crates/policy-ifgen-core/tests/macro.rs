pub mod tictactoe {
    policy_ifgen_macro::interface!("tests/data/tictactoe.md");

    pub fn doit(a: &mut impl Actor) -> Result<(), runtime::ClientError> {
        let id = policy_vm::Id::default();
        a.MakeMove(id, 1, 2)
    }

    #[test]
    fn parse_effects() {
        #![allow(non_snake_case)]

        use policy_vm::{Id, KVPair};

        let gameID = Id::default();
        let winner = Id::default();
        let p = String::from("p field");

        let order1 = vec![
            KVPair::new("gameID", gameID.into()),
            KVPair::new("winner", winner.into()),
            KVPair::new("p", p.clone().into()),
        ];

        let order2 = vec![
            KVPair::new("winner", winner.into()),
            KVPair::new("p", p.clone().into()),
            KVPair::new("gameID", gameID.into()),
        ];

        let parsed = GameOver { gameID, winner, p };

        assert_eq!(parsed, order1.try_into().unwrap());

        assert_eq!(parsed, order2.try_into().unwrap());
    }
}

pub mod ttc {
    policy_ifgen_macro::interface!("tests/data/ttc.md");

    pub fn doit(a: &mut impl Actor) -> Result<(), runtime::ClientError> {
        let name = String::from("foobar");
        a.create_aps_label(name, 42)
    }
}
