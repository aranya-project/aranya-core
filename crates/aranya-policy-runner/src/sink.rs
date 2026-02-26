use aranya_runtime::{Sink, VmEffect};

/// A [`Sink`] that prints effects to `stdout` when it is committed.
#[derive(Default)]
pub struct EchoSink {
    buffer: Vec<VmEffect>,
}

impl Sink<VmEffect> for EchoSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: VmEffect) {
        self.buffer.push(effect);
    }

    fn rollback(&mut self) {
        self.buffer.clear();
    }

    fn commit(&mut self) {
        for e in &self.buffer {
            println!("{e}");
        }
        self.buffer.clear();
    }
}
