//! Interface for collecting runtime metrics.
//!
//! [`Metrics`] provide an API to collect information about operations preformed within the Aranya runtime.

use core::{
    fmt::{self, Display},
    time::Duration,
};

/// [`Metrics`] provides an interface to push a named [`Metric`] to a collection.
pub trait Metrics {
    type Error: trouble::Error + Send + Sync + 'static;

    fn update(&mut self, name: &'static str, metric: Metric) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum Metric {
    Count(u64),
    Duration(Duration),
}

#[derive(Debug)]
pub enum MetricError {
    IncorrectType,
    UnknownMetric,
}

impl Display for MetricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectType => write!(f, "metric type is incompatible"),
            Self::UnknownMetric => write!(f, "Metric cannot be found"),
        }
    }
}
