#[path = "../tests/data/tictactoe.rs"]
pub mod tictactoe;

use aranya_policy_ifgen::{Actionable, BaseId};
use aranya_policy_vm::text;

use crate::tictactoe::Players;

struct PrintClient;
impl PrintClient {
    fn act(&mut self, action: impl Actionable<Interface = tictactoe::Persistent>) {
        action.with_action(|action| {
            println!("Calling persistent action {action}");
        });
    }

    fn session_act(&mut self, action: impl Actionable<Interface = tictactoe::Ephemeral>) {
        action.with_action(|action| {
            println!("Calling ephemeral action {action}");
        });
    }
}

fn main() {
    let mut client = PrintClient;
    client.act(tictactoe::StartGame(Players {
        X: BaseId::default(),
        O: BaseId::default(),
    }));
    client.session_act(tictactoe::Temporary(42, text!("asdf")));
}
