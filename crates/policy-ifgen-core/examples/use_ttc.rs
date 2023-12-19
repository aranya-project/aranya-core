#[rustfmt::skip]
#[path = "../tests/data/ttc.rs"]
mod ttc;

use policy_vm::Id;
use ttc::Actor;

struct PrintClient;
impl Actor for PrintClient {
    fn call_action(
        &mut self,
        (name, args): ttc::VmActions<'_>,
    ) -> Result<(), runtime::ClientError> {
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
