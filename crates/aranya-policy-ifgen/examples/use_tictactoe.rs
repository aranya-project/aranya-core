#[rustfmt::skip]
#[path = "../tests/data/tictactoe.rs"]
pub mod tictactoe;

use aranya_policy_ifgen::{Actor, ClientError, Id, VmAction};
use tictactoe::{ActorExt, Players};

struct PrintClient;
impl Actor for PrintClient {
    fn call_action(&mut self, action: VmAction<'_>) -> Result<(), ClientError> {
        println!("Called {action}");
        Ok(())
    }
}

fn main() {
    let mut client = PrintClient;
    client
        .StartGame(Players {
            X: Id::default(),
            O: Id::default(),
        })
        .expect("no panic");
}
