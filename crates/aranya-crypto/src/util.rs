/// Either `L` or `R`.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Either<L, R> {
    Left(L),
    Right(R),
}
