use std::{collections::HashMap, convert::Infallible, marker::PhantomData};

use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Engine, Id, Rng,
};
use aranya_policy_vm::{
    self,
    ffi::{ffi, FfiModule, Type},
    CommandContext, MachineError, MachineErrorType, MachineStack, PolicyContext, Stack, Typed,
    Value, ValueConversionError,
};

#[derive(Debug, PartialEq)]
enum TestStateError<E>
where
    E: Into<MachineError>,
{
    UnknownFunc,
    Module(E),
}

struct TestState<M, E> {
    module: M,
    procs: HashMap<String, usize>,
    stack: MachineStack,
    engine: E,
}

impl<M: FfiModule> TestState<M, DefaultEngine<Rng>> {
    fn new(module: M) -> Self {
        let (engine, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
        let procs = M::SCHEMA
            .functions
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.to_owned(), i))
            .collect();
        Self {
            module,
            procs,
            stack: MachineStack::new(),
            engine,
        }
    }

    fn call(&mut self, name: &str) -> Result<(), TestStateError<M::Error>> {
        let ctx = CommandContext::Policy(PolicyContext {
            name: "SomeCommand",
            id: Id::default(),
            author: Id::default().into(),
            version: Id::default(),
        });
        let idx = self.procs.get(name).ok_or(TestStateError::UnknownFunc)?;
        self.module
            .call(*idx, &mut self.stack, &ctx, &mut self.engine)
            .map_err(TestStateError::Module)
    }

    fn push<V>(&mut self, v: V)
    where
        V: Into<Value>,
    {
        self.stack.push(v).expect("should not fail")
    }

    fn pop<V>(&mut self) -> Result<V, MachineErrorType>
    where
        V: TryFrom<Value, Error = ValueConversionError>,
    {
        self.stack.pop()
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    fn len(&self) -> usize {
        self.stack.len()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Label(u32);

impl Typed for Label {
    const TYPE: Type<'static> = Type::Int;
}

impl From<Label> for Value {
    fn from(label: Label) -> Self {
        Value::Int(label.0.into())
    }
}

impl TryFrom<Value> for Label {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let x = match value {
            Value::Int(x) => x,
            _ => return Err(ValueConversionError::InvalidType),
        };
        Ok(Label(
            u32::try_from(x).map_err(|_| ValueConversionError::OutOfRange)?,
        ))
    }
}

struct Overflow;

impl From<Overflow> for MachineError {
    fn from(_err: Overflow) -> Self {
        MachineError::new(MachineErrorType::IntegerOverflow)
    }
}

struct TestModule<'a, T, G> {
    _x: Option<&'a i64>,
    _t: PhantomData<T>,
    _g: PhantomData<G>,
}

impl<'a, T, G> TestModule<'a, T, G> {
    fn new() -> Self {
        Self {
            _x: None,
            _t: PhantomData,
            _g: PhantomData,
        }
    }

    const NO_ARGS_RESULT: i64 = 42;
    const CUSTOM_TYPE_ARG: Label = Label(1234);
    const CUSTOM_TYPE_RESULT: Label = Label(4321);
}

#[ffi(
    module = "test",
    def = r#"
struct S0 {
    x int
}
struct S1 {
    a string,
    b bytes,
    c int,
    d bool,
    e id,
    f struct S0,
    g optional int,
}
struct S2 {
    a struct S0,
    b struct S1,
}
"#
)]
impl<'a, T, G> TestModule<'a, T, G> {
    #[ffi_export(def = "function add(x int, y int) int")]
    fn add<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        x: i64,
        y: i64,
    ) -> Result<i64, Overflow> {
        x.checked_add(y).ok_or(Overflow)
    }

    #[ffi_export(def = "function sub(x int, y int) int")]
    fn sub<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        x: i64,
        y: i64,
    ) -> Result<i64, Overflow> {
        x.checked_sub(y).ok_or(Overflow)
    }

    #[ffi_export(def = "function concat(a string, b string) string")]
    fn concat<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        a: String,
        b: String,
    ) -> Result<String, MachineError> {
        Ok(a + b.as_str())
    }

    #[ffi_export(def = "function renamed_identity(id_input id) id")]
    fn identity<E: Engine>(
        &self,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        id_input: Id,
    ) -> Result<Id, Infallible> {
        Ok(id_input)
    }

    #[ffi_export(def = "function no_args() int")]
    fn no_args<E: Engine>(
        &self,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
    ) -> Result<i64, MachineError> {
        Ok(Self::NO_ARGS_RESULT)
    }

    #[ffi_export(def = "function custom_type(label int) int")]
    fn custom_type<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        label: Label,
    ) -> Result<Label, Infallible> {
        assert_eq!(label, Self::CUSTOM_TYPE_ARG);
        Ok(Self::CUSTOM_TYPE_RESULT)
    }

    #[ffi_export(def = "function custom_type_optional(label optional int) optional int")]
    fn custom_type_optional<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        label: Option<Label>,
    ) -> Result<Option<Label>, Infallible> {
        assert_eq!(label, Some(Self::CUSTOM_TYPE_ARG));
        Ok(Some(Self::CUSTOM_TYPE_RESULT))
    }

    #[ffi_export(def = "function custom_def(a int, b bytes) bool")]
    fn custom_def<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        _a: i64,
        _b: Vec<u8>,
    ) -> Result<bool, Infallible> {
        Ok(true)
    }

    #[ffi_export(def = r#"
function struct_fn(
    a struct S0,
    b struct S1,
) struct S2
"#)]
    fn struct_fn<E: Engine>(
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
        a: S0,
        b: S1,
    ) -> Result<S2, Infallible> {
        Ok(S2 { a, b })
    }

    #[allow(dead_code)]
    fn ignored(&self, _a: Vec<u8>) -> Result<(), MachineError> {
        Ok(())
    }
}

// TODO(eric): break these into their own test routines.
#[test]
fn test_ffi_derive() {
    let mut state = TestState::new(TestModule::<'_, (), ()>::new());

    // Positive test case for `add`.
    {
        state.push(1i64);
        state.push(2i64);
        state.call("add").expect("`test::add` should not fail");
        let got = state.pop::<i64>().expect("should have got an `i64`");
        assert_eq!(got, 3, "`test::add` returned the wrong result");
        assert!(state.is_empty());
    }

    // Negative test case for `add`.
    {
        state.push(i64::MAX);
        state.push(1i64);
        let err = state
            .call("add")
            .expect_err("`test::sub` should have failed");
        assert_eq!(
            err,
            TestStateError::Module(MachineError::new(MachineErrorType::IntegerOverflow)),
            "`add` should have returned `Overflow`",
        );
        assert!(state.is_empty());
    }

    // Positive test case for `sub`.
    {
        state.push(10i64);
        state.push(2i64);
        state.call("sub").expect("`test::sub` should not fail");
        let got = state.pop::<i64>().expect("should have got an `i64`");
        assert_eq!(got, 8, "`test::sub` returned the wrong result");
        assert!(state.is_empty());
    }

    // Negative test case for `sub`.
    {
        state.push(i64::MIN);
        state.push(2i64);
        let err = state
            .call("sub")
            .expect_err("`test::sub` should have failed");
        assert_eq!(
            err,
            TestStateError::Module(MachineError::new(MachineErrorType::IntegerOverflow)),
            "`test::sub` should have returned `Overflow`",
        );
        assert!(state.is_empty());
    }

    // Positive test case for `concat`
    {
        state.push("hello, ");
        state.push("world!");
        state
            .call("concat")
            .expect("`test::concat` should not fail");
        let got = state.pop::<String>().expect("should have got a `String`");
        assert_eq!(
            got, "hello, world!",
            "`test::concat` returned the wrong result",
        );
        assert!(state.is_empty());
    }

    // Positive test for `identity`.
    {
        let a = Id::default();
        let b = Id::random(&mut Rng);

        state.push(b);
        state.push(a);

        for (id, len) in [(a, 1), (b, 0)] {
            state
                .call("renamed_identity")
                .expect("`test::renamed_identity` should not fail");
            let got = state.pop::<Id>().expect("should have got an `Id`");
            assert_eq!(
                got, id,
                "`test::renamed_identity` returned the wrong result"
            );
            assert_eq!(state.len(), len, "should be one argument remaining");
        }
    }

    // Positive test for `no_args`.
    {
        state.push("existing arg");
        state
            .call("no_args")
            .expect("`test::no_args` should not fail");
        let got = state.pop::<i64>().expect("should have got an `i64`");
        assert_eq!(
            got,
            TestModule::<(), ()>::NO_ARGS_RESULT,
            "`test::no_args` returned the wrong result`"
        );
        assert_eq!(state.len(), 1, "should be one item on the stack");
        let got = state.pop::<String>().expect("should have got a `String`");
        assert_eq!(got, "existing arg", "existing stack item is incorrect");
    }

    // Positive test for `custom_type`.
    {
        state.push(TestModule::<(), ()>::CUSTOM_TYPE_ARG);
        state
            .call("custom_type")
            .expect("`test::custom_type` should not fail");
        let got = state.pop::<Label>().expect("should have got a `Label`");
        assert_eq!(
            got,
            TestModule::<(), ()>::CUSTOM_TYPE_RESULT,
            "`test::custom_type` returned the wrong result`"
        );
        assert!(state.is_empty());
    }

    // Positive test for `custom_def`.
    {
        state.push(0i64);
        state.push(Vec::new());
        state
            .call("custom_def")
            .expect("`test::custom_def` should not fail");
        let got = state.pop::<bool>().expect("should have got a `bool`");
        assert!(got, "`test::custom_def` returned the wrong result`");
        assert!(state.is_empty());
    }

    // Positive test for `struct_fn`.
    {
        use __test_ffi::{S0, S1, S2};

        let a = S0 { x: 42 };
        let b = S1 {
            a: "hello, world!".to_owned(),
            b: vec![1, 2, 3, 4],
            c: 42,
            d: true,
            e: Id::random(&mut Rng),
            f: S0 { x: 1234 },
            g: Some(42),
        };
        state.push(a.clone());
        state.push(b.clone());
        state
            .call("struct_fn")
            .expect("`test::struct_fn` should not fail");
        let got = state.pop::<S2>().expect("should have got an `S2`");
        assert_eq!(got, S2 { a, b });
        assert!(state.is_empty());
    }
}
