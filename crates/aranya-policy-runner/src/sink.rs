use std::{
    io::{self, Write},
    path::Path,
};

use aranya_runtime::{Sink, VmEffect};

/// A [`Sink`] that prints effects to `stdout` when it is committed.
pub struct WriterSink<'o> {
    buffer: Vec<VmEffect>,
    writer: &'o mut dyn Write,
}

impl<'o> WriterSink<'o> {
    pub fn new(writer: &'o mut dyn Write) -> Self {
        Self {
            buffer: Vec::new(),
            writer,
        }
    }

    pub fn mark(&mut self, path: &Path) -> io::Result<()> {
        writeln!(self.writer, "--- {}", path.display())
    }
}

impl<'o> Sink<VmEffect> for WriterSink<'o> {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: VmEffect) {
        self.buffer.push(effect);
    }

    fn rollback(&mut self) {
        self.buffer.clear();
    }

    fn commit(&mut self) {
        for e in &self.buffer {
            writeln!(self.writer, "{e}").expect("could not write to output");
        }
        self.buffer.clear();
    }
}
