#[rustfmt::skip]
#[path = "../tests/data/ttc.rs"]
pub mod ttc;

use aranya_policy_ifgen::{Actor, ClientError, Id, VmAction};
use ttc::ActorExt;

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
        .assign_afc_label(Id::default(), 42, String::from("foo"))
        .expect("no panic");
}
