//! Interface for collecting runtime metrics.
//!
//! [`Metrics`] provide an API to collect information about operations preformed within the Aranya runtime.

use core::time::Duration;

/// [`Metrics`] provides an interface to push a named [`Metric`] to a collection.
pub trait Metrics {
    type Error: core::error::Error + Send + Sync + 'static;

    fn update(&mut self, name: &'static str, metric: Metric) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Metric {
    Count(u64),
    Duration(Duration),
}

#[derive(Debug, thiserror::Error)]
pub enum MetricError {
    #[error("metric type is incompatible")]
    IncorrectType,
    #[error("metric cannot be found")]
    UnknownMetric,
}
