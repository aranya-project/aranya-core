//! SpiraTeam Integration
//!
//! The [`spira`][macro@crate::spira] macro records the result of
//! a unit test. For example:
//!
//! ```no_run
//! #[test]
//! #[rtrack::spira(
//!     project_id = 4,
//!     test_cases = [1, 2, 3, 4],
//! )]
//! fn test_whatever() {
//!     assert_eq!(1+2, 3);
//! }
//!
//! #[test]
//! #[rtrack::spira(
//!     project_id = 2,
//!     test_cases = [6],
//! )]
//! #[should_panic]
//! fn test_panics() {
//!     panic!("oops")
//! }
//! ```
//!
//! It has the following fields:
//!
//! * `name`: the project name.
//! * `tests`: the list of test cases that this unit test covers.
//!
//! # Configuration
//!
//! By default, the following configuration options are are read
//! from environment variables at runtime.
//!
//! Setting `SPIRA_ENABLED` to any value enables the Spira
//! integration. This is opt-in to simplify local development.
//!
//! `SPIRA_RECORDER` dictates where test output should be
//! recorded. If left unset, it defaults to `http`. It accepts
//! the following options:
//!
//! * `http`: send each test result to Spira via HTTP.
//! * `stdout`: print each test result to stdout.
//! * `file=path`: append each test result to `path`.
//!
//! Multiple recorders can be selected by delimiting them with
//! commas. For example:
//!
//! ```text
//! SPIRA_RECORDER=stdout,file=/tmp/output.txt
//! ```
//!
//! Duplicate recorders are ignored.
//!
//! The following environment variables are required if the
//! `http` recorder is selected:
//!
//! * `SPIRA_API_KEY`: the RSS token created by the Spira
//!    application.
//! * `SPIRA_API_USERNAME`: the Spira username.
//! * `SPIRA_BASE_URL`: the base URL used to access the API. For
//!    example, `https://companyname.spiraservice.net/`.
//!
//! There are several optional configuration options. These are
//! only read from environment variables at compile time.
//!
//! * `SPIRA_BUILD_ID`: the `i32` ID of the build the tests are
//!   being executed against.
//! * `SPIRA_RELEASE_ID`: the `i32` ID of the release that the
//!   test run should be reported against.
//!
//! # Bugs
//!
//! * Does not correctly handle tests that time out.

#![cfg_attr(docs, doc(cfg(feature = "spira")))]
#![cfg(feature = "spira")]

use std::{
    backtrace::Backtrace,
    borrow::Cow,
    cell::RefCell,
    collections::HashSet,
    fmt, panic,
    sync::{Arc, Mutex, Once},
    thread,
};

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;

use crate::spira::{
    api::{ArtifactId, ExecutionStatusId, TestRun, TestRunFormatId, TestRunTypeId},
    config::getcfg,
    sender::{Http, Sender, Tee, Writer},
};

mod api;
mod config;
mod sender;

/// A particular unit test.
///
/// This struct is created by the `rtrack-derive` crate.
#[doc(hidden)]
pub struct Test {
    /// The test name.
    pub name: &'static str,
    /// The project ID.
    pub project_id: i32,
    /// The project tests that this maps to.
    pub tests: &'static [i32],
    /// Does the test have a `#[should_panic]` marker?
    pub should_panic: bool,
}

/// Runs and records a unit test that returns `()`.
///
/// Used by the generated code in `rtrack-derive`.
#[doc(hidden)]
pub fn run_test_unit(t: &Test, f: fn()) {
    let start = Utc::now();
    let _ = record(
        t,
        start,
        panic::catch_unwind(|| {
            f();
            Ok::<(), ()>(())
        }),
    );
}

/// Runs and records unit test that returns `Result<T, E>`.
///
/// Used by the generated code in `rtrack-derive`.
#[doc(hidden)]
pub fn run_test_result<T, E>(t: &Test, f: fn() -> Result<T, E>) -> Result<T, E>
where
    E: fmt::Debug,
{
    let start = Utc::now();
    record(t, start, panic::catch_unwind(f))
}

lazy_static! {
    /// Contains a backtrace from a crashing thread.
    static ref BACKTRACE: Arc<Mutex<Option<Backtrace>>> = Arc::new(Mutex::new(None));
}

/// Called by `record`.
fn init() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            *BACKTRACE.lock().expect("poisoned") = Some(Backtrace::force_capture());
            prev(info)
        }));
    });
}

thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = RefCell::new(None);
}

/// Records the result of the test.
fn record<T, E>(
    t: &Test,
    start: DateTime<Utc>,
    result: thread::Result<Result<T, E>>,
) -> Result<T, E>
where
    E: fmt::Debug,
{
    init();

    /// Retrieves the current backtrace.
    fn backtrace() -> Option<String> {
        BACKTRACE
            .lock()
            .expect("poisoned")
            .as_ref()
            .map(|b| b.to_string())
    }

    let res = RECORDER.with_borrow_mut(|v| -> Result<Result<T, E>, anyhow::Error> {
        let stop = Utc::now();
        let rec = v.get_or_insert_with(|| {
            let v = getcfg!(SPIRA_RECORDER);
            Recorder::new(&v).expect("unable to create `Recorder`")
        });
        match result {
            // No panic.
            Ok(inner) => {
                match &inner {
                    Ok(_) if !t.should_panic => rec.pass(t, start, stop)?,
                    Ok(_) => rec.fail(t, start, stop, &ExpectedPanic, None)?,
                    Err(err) => rec.fail(t, start, stop, &err, backtrace())?,
                }
                rec.flush()?;
                Ok(inner)
            }
            // The test panicked.
            Err(err) => {
                if t.should_panic {
                    rec.pass(t, start, stop)?
                } else {
                    rec.fail(t, start, stop, &err, backtrace())?
                }
                rec.flush()?;
                panic::resume_unwind(err)
            }
        }
    });
    res.expect("unable to record test result")
}

#[derive(Debug)]
struct ExpectedPanic;

impl fmt::Display for ExpectedPanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "test should have panicked, but did not")
    }
}

/// Contains generated build time information.
#[allow(dead_code)]
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_info.rs"));
}

/// The name of the tool that executed the tests.
const RUNNER_NAME: &str = "rtrack";

/// A possible match pattern.
enum Needle<'a> {
    /// Matches a prefix.
    ///
    /// [`find_match`] will return [`Match::Prefix`].
    Prefix(&'a str),
    /// Matches an entire string.
    ///
    /// [`find_match`] will return [`Match::Complete`].
    Complete(&'a str),
}

/// The result from [`find_match`].
#[derive(Debug)]
enum Match<'a> {
    /// Did not find a match.
    ///
    /// It returns the haystack.
    None(&'a str),
    /// Found a prefix match ([`Needle::Prefix`]).
    Prefix { prefix: &'a str, suffix: &'a str },
    /// Found a complete match ([`Needle::Complete`]).
    Complete(&'a str),
}

/// Finds the first needle in `haystack`.
fn find_match<'a, I>(haystack: &'a str, needles: I) -> Match<'a>
where
    I: IntoIterator<Item = Needle<'a>>,
{
    for needle in needles {
        match needle {
            Needle::Prefix(prefix) => match haystack
                .strip_prefix(prefix)
                .map(|suffix| Match::Prefix { prefix, suffix })
            {
                Some(m) => return m,
                None => continue,
            },
            Needle::Complete(s) if s == haystack => return Match::Complete(s),
            _ => continue,
        }
    }
    Match::None(haystack)
}

struct Recorder {
    sender: Tee,
}

impl Recorder {
    /// Creates a new recorder
    fn new(which: &str) -> anyhow::Result<Self> {
        fn new_sender(segment: &str) -> anyhow::Result<Box<dyn Sender>> {
            const NEEDLES: [Needle<'static>; 3] = [
                Needle::Complete("http"),
                Needle::Complete("stdout"),
                Needle::Prefix("file="),
            ];
            match find_match(segment, NEEDLES) {
                Match::Complete("http") => Ok(Box::new(Http::new(
                    getcfg!(SPIRA_BASE_URL),
                    getcfg!(SPIRA_API_USERNAME),
                    getcfg!(SPIRA_API_KEY),
                )?)),
                Match::Complete("stdout") => Ok(Box::new(Writer::stdout())),
                Match::Prefix {
                    prefix: "file=",
                    suffix,
                } => Ok(Box::new(Writer::file(suffix)?)),
                etc => Err(anyhow!("unknown `SPIRA_RECORDER`: {etc:?}")),
            }
        }

        println!("senders = {:?}", which.split(',').collect::<HashSet<_>>());

        let senders = which
            .split(',')
            .collect::<HashSet<_>>()
            .into_iter()
            .map(new_sender)
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self {
            sender: sender::tee(senders),
        })
    }

    /// Flushes all test results.
    fn flush(&mut self) -> anyhow::Result<()> {
        self.sender.flush()
    }

    /// Sends the test run result.
    fn send(&mut self, run: &TestRun<'_>) -> anyhow::Result<()> {
        self.sender.send(run)
    }

    /// Marks the test as passing.
    pub fn pass(
        &mut self,
        t: &Test,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        for id in t.tests.iter().copied() {
            let req = TestRun {
                test_run_format_id: TestRunFormatId::Plain,
                runner_name: Some(Cow::Borrowed(RUNNER_NAME)),
                runner_test_name: Some(Cow::Borrowed(t.name)),
                // The REST API states that this is required,
                // which means we shouldn't use `None`. But their
                // SOAP says it's optional.
                runner_stack_trace: None,
                name: Some(Cow::Borrowed(t.name)),
                test_case_id: id,
                test_run_type_id: TestRunTypeId::Automated,
                execution_status_id: ExecutionStatusId::Passed,
                release_id: getcfg!(SPIRA_RELEASE_ID),
                start_date: start,
                end_date: Some(end),
                build_id: getcfg!(SPIRA_BUILD_ID),
                project_id: t.project_id,
                artifact_type_id: ArtifactId::TestRun,
                concurrency_date: start,
                ..TestRun::default()
            };
            self.send(&req)
                .with_context(|| format!("unable to record result for test case {id}"))?
        }
        Ok(())
    }

    /// Marks the test as failing.
    pub fn fail<E>(
        &mut self,
        t: &Test,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        err: &E,
        bt: Option<String>,
    ) -> anyhow::Result<()>
    where
        E: fmt::Debug,
    {
        let msg = format!("{:#?}", err);

        for id in t.tests.iter().copied() {
            let req = TestRun {
                test_run_format_id: TestRunFormatId::Plain,
                runner_name: Some(Cow::Borrowed(RUNNER_NAME)),
                runner_test_name: Some(Cow::Borrowed(t.name)),
                runner_assert_count: Some(1),
                runner_message: Some(Cow::Borrowed(&msg)),
                runner_stack_trace: bt.as_deref().map(Cow::Borrowed),
                name: Some(Cow::Borrowed(t.name)),
                test_case_id: id,
                test_run_type_id: TestRunTypeId::Automated,
                execution_status_id: ExecutionStatusId::Failed,
                release_id: getcfg!(SPIRA_RELEASE_ID),
                start_date: start,
                end_date: Some(end),
                build_id: getcfg!(SPIRA_BUILD_ID),
                project_id: t.project_id,
                artifact_type_id: ArtifactId::TestRun,
                concurrency_date: start,
                ..TestRun::default()
            };
            self.send(&req)
                .with_context(|| format!("unable to record result for test case {id}"))?
        }
        Ok(())
    }
}
