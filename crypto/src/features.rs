#[cfg(not(feature = "result_option_inspect"))]
pub(crate) trait ResultInspect<T, E> {
    fn inspect<F: FnOnce(&T)>(self, f: F) -> Self;
    fn inspect_err<F: FnOnce(&E)>(self, f: F) -> Self;
}

#[cfg(not(feature = "result_option_inspect"))]
impl<T, E> ResultInspect<T, E> for Result<T, E> {
    fn inspect_err<F: FnOnce(&E)>(self, f: F) -> Self {
        if let Err(ref e) = self {
            f(e);
        }
        self
    }

    fn inspect<F: FnOnce(&T)>(self, f: F) -> Self {
        if let Ok(ref t) = self {
            f(t);
        }
        self
    }
}
