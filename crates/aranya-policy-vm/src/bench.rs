//! Allows timing of code, aggregation of results, and calculating statistics.
//!
//! First, enable the benchmarking feature in `runtime/Cargo.toml`:
//!
//! ```toml
//! [features]
//! default = ["bench"]
//! ```
//!
//! Measure how long something takes:
//!
//! ```
//! use aranya_policy_vm::Stopwatch;
//!
//! fn do_something() {}
//!
//! let mut sw = Stopwatch::new();
//! for i in 0..10 {
//!     sw.start("do_something");
//!     do_something();
//!     sw.stop();
//! }
//! sw.measurements.print_stats();
//! ```
//!
//! Collect measurements from multiple stopwatches
//!
//! ```
//! use aranya_policy_vm::{Stopwatch, bench_aggregate, bench_measurements};
//!
//! let mut sw1 = Stopwatch::new();
//! let mut sw2 = Stopwatch::new();
//!
//! // benchmark using `start()/stop()`...
//!
//! bench_aggregate(&mut sw1);
//! bench_aggregate(&mut sw2);
//! bench_measurements().print_stats();
//! ```

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::{fmt::Display, ops::Div};
use std::{
    fmt,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use table_formatter::{cell, table, table::Align};

/// Measures and records times for named tasks.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Stopwatch {
    /// Stack of measurement contexts.
    pub measurement_stack: Vec<(String, Instant)>,

    /// Names and times
    pub measurements: BenchMeasurements,
}

impl Stopwatch {
    /// Creates a new stopwatch
    pub fn new() -> Self {
        Self {
            measurement_stack: Vec::new(),
            measurements: BenchMeasurements::new(),
        }
    }

    /// Starts recording time
    #[inline(never)]
    pub fn start(&mut self, name: &str) {
        self.measurement_stack
            .push((String::from(name), Instant::now()));
    }

    /// Stops recording time, and records the the duration (since `start()`) in `measurements`.
    #[inline(never)]
    pub fn stop(&mut self) -> Duration {
        let (name, start) = self
            .measurement_stack
            .pop()
            .expect("should have started a measurement before stopping");
        let duration = start.elapsed();
        self.measurements.record(name, duration);
        duration
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds durations
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BenchMeasurements(BTreeMap<String, Vec<Duration>>);

impl BenchMeasurements {
    /// Creates a new `BenchMeasurements` object
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Record a measurement
    pub fn record(&mut self, name: String, duration: Duration) {
        self.0.entry(name).or_default().push(duration);
    }

    /// Computes benchmarking statistics from the accumulated measurements. The returned values are sorted by mean time, in descending order.
    pub fn stats(&self) -> Vec<BenchStat> {
        if self.0.is_empty() {
            return vec![];
        }
        let mut m: Vec<BenchStat> = self
            .0
            .iter()
            .map(|(name, measurements)| {
                let best = *measurements
                    .iter()
                    .min()
                    .expect("should have a measurement");
                let worst = *measurements
                    .iter()
                    .max()
                    .expect("should have a measurement");
                let count: u32 = measurements
                    .len()
                    .try_into()
                    .expect("should convert len to u32");
                let mean = measurements
                    .iter()
                    .fold(Duration::from_nanos(0), |acc, m| acc.saturating_add(*m))
                    .div_f64(f64::from(count));

                // variance
                let mean_ns = mean.as_nanos();
                #[allow(clippy::cast_precision_loss)]
                let variance = (measurements.iter().fold(0_u128, |acc, m| {
                    let v = m.as_nanos().abs_diff(mean_ns).pow(2);
                    acc.saturating_add(v)
                }) as f64)
                    .div(f64::from(count));
                let std_dev = f64::sqrt(variance);
                #[allow(clippy::cast_sign_loss)]
                let std_dev = Duration::from_nanos(std_dev as u64);

                BenchStat {
                    name: name.clone(),
                    num_samples: count,
                    best,
                    worst,
                    mean,
                    std_dev,
                }
            })
            .collect();
        m.sort_by(|a, b| b.mean.cmp(&a.mean));
        m
    }

    /// Prints benchmarking stats
    pub fn print_stats(&self) {
        let header = vec![
            cell!("Name"),
            cell!("# Samples"),
            cell!("Best"),
            cell!("Worst"),
            cell!("Mean"),
            cell!("SD"),
        ];
        let cells = {
            self.stats()
                .iter()
                .map(|s| {
                    vec![
                        cell!(s.name.clone()),
                        cell!(s.num_samples, align = Align::Right),
                        cell!(format!("{:?}", s.best), align = Align::Right),
                        cell!(format!("{:?}", s.worst), align = Align::Right),
                        cell!(format!("{:?}", s.mean), align = Align::Right),
                        cell!(format!("{:?}", s.std_dev), align = Align::Right),
                    ]
                })
                .collect()
        };
        let table = table! {
            header
            ---
            cells
        };
        let mut buf = vec![];
        table.render(&mut buf).expect("table should render");
        println!(
            "{}",
            String::from_utf8(buf).expect("table should convert to string")
        );
    }
}

impl Default for BenchMeasurements {
    fn default() -> Self {
        Self::new()
    }
}

/// Benchmarking statistics
pub struct BenchStat {
    name: String,
    num_samples: u32,
    best: Duration,
    worst: Duration,
    mean: Duration,
    std_dev: Duration,
}

impl Display for BenchStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: ({} samples), best: {:?}, worst: {:?}, mean: {:?}, SD: {:?}",
            self.name, self.num_samples, self.best, self.worst, self.mean, self.std_dev
        )
    }
}

static MEASUREMENTS: Mutex<BenchMeasurements> = Mutex::new(BenchMeasurements(BTreeMap::new()));

/// Adds the given measurements to the global measurements.
pub fn bench_aggregate(stopwatch: &mut Stopwatch) {
    let mut m = MEASUREMENTS.lock().expect("poisoned");

    for (key, mut value) in core::mem::take(&mut stopwatch.measurements.0) {
        m.0.entry(key)
            .and_modify(|e| e.append(&mut value))
            .or_insert(value);
    }
    if !stopwatch.measurement_stack.is_empty() {
        println!("Incomplete measurements:");
        for (name, _) in stopwatch.measurement_stack.iter() {
            println!("{name}");
        }
    }
}

/// Returns the accumulated benchmarking measurements.
pub fn bench_measurements() -> MutexGuard<'static, BenchMeasurements> {
    MEASUREMENTS.lock().expect("poisoned")
}
