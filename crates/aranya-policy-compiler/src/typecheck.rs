mod check;
mod types;

use crate::{ctx::Ctx, hir::Hir};

pub(crate) type Result<T, E = String> = std::result::Result<T, E>;

impl Ctx<'_> {
    pub fn typecheck(&mut self, hir: &Hir) -> Result<()> {
        todo!()
    }
}
