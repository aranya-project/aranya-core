#[rustfmt::skip]
#[path = "../tests/data/ttc.rs"]
pub mod ttc;

use policy_ifgen::Id;
use ttc::ActorExt;

struct PrintClient;
impl policy_ifgen::Actor for PrintClient {
    fn call_action(
        &mut self,
        (name, args): policy_ifgen::VmActions<'_>,
    ) -> Result<(), policy_ifgen::ClientError> {
        println!("Called {name}({args:?})");
        Ok(())
    }
}

fn main() {
    let mut client = PrintClient;
    client
        .assign_aps_label(Id::default(), 42, String::from("foo"))
        .expect("no panic");
}
