//! Implements v7 of the SpiraTeam API.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Spira's `DateTime` format.
mod date_time_format {
    use chrono::{DateTime, Utc};
    use serde::{de, Deserialize, Deserializer, Serializer};

    const FORMAT: &str = "%Y-%m-%dT%H%M:%S.%3f";

    pub fn serialize<S>(date: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&format!("{}", date.format(FORMAT)))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let dt = DateTime::parse_from_str(&s, FORMAT).map_err(de::Error::custom)?;
        Ok(dt.with_timezone(&Utc))
    }
}

/// Same as `date_time_format`, but for `Option<DateTime>`.
mod opt_date_time_format {
    use core::fmt;

    use chrono::{DateTime, Utc};
    use serde::{self, de, Deserializer, Serializer};

    use super::date_time_format;

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            None => s.serialize_none(),
            Some(d) => date_time_format::serialize(d, s),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionDateTimeVisitor;
        impl<'de> de::Visitor<'de> for OptionDateTimeVisitor {
            type Value = Option<DateTime<Utc>>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an optional `DateTime`")
            }

            fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                date_time_format::deserialize(d).map(Some)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }
        }
        d.deserialize_option(OptionDateTimeVisitor)
    }
}

fn is_false(b: &bool) -> bool {
    !b
}

#[repr(i32)]
#[derive(Copy, Clone, Default, Serialize_repr, Deserialize_repr)]
pub(crate) enum ArtifactId {
    Requirement = 1,
    TestCase = 2,
    Incident = 3,
    Release = 4,
    #[default]
    TestRun = 5,
    Task = 6,
    TestStep = 7,
    TestSet = 8,
    AutomationHost = 9,
    AutomationEngine = 10,
    RequirementStep = 12,
    Document = 13,
    Risk = 14,
    RiskMitigation = 15,
}

#[repr(i32)]
#[derive(Copy, Clone, Default, Serialize_repr, Deserialize_repr)]
pub(crate) enum ExecutionStatusId {
    #[default]
    Failed = 1,
    Passed = 2,
    NotRun = 3,
    NotApplicable = 4,
    Blocked = 5,
    Caution = 6,
}

#[repr(i32)]
#[derive(Copy, Clone, Default, Serialize_repr, Deserialize_repr)]
pub(crate) enum TestRunFormatId {
    #[default]
    Plain = 1,
    Html = 2,
}

#[repr(i32)]
#[derive(Copy, Clone, Default, Serialize_repr, Deserialize_repr)]
pub(crate) enum TestRunTypeId {
    Manual = 1,
    #[default]
    Automated = 2,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RemoteArtifactCustomProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boolean_value: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_time_value: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub integer_list_value: Vec<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub integer_value: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
}

/// Represents a test set test case parameter (used when you have
/// a test set pass parameters through to mapped test cases).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RemoteTestSetTestCaseParameter {
    /// The name of the test parameter.
    pub name: Option<String>,
    /// The guid of the test case parameter.
    pub test_case_parameter_guid: Option<String>,
    /// The id of the test case parameter. Required.
    pub test_case_parameter_id: i32,
    /// The id of the test set test case. Required.
    pub test_case_set_id: i32,
    /// The value of the parameter to be passed from the test set
    /// to the test case.
    pub value: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RemoteTestRunStep {
    /// ???
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_run_step_id: Option<i32>,

    /// ???
    pub test_run_id: i32,

    /// ???
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_step_id: Option<i32>,

    /// ???
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_case_id: Option<i32>,

    /// ???
    pub execution_status_id: ExecutionStatusId,

    /// ???
    pub position: i32,

    /// ???
    pub description: String,

    /// ???
    pub expected_result: String,

    /// ???
    pub sample_data: String,

    /// ???
    pub actual_result: String,

    /// ???
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_duration: Option<i32>,

    /// ???
    #[serde(skip_serializing_if = "Option::is_none", with = "opt_date_time_format")]
    pub start_time: Option<DateTime<Utc>>,

    /// ???
    #[serde(skip_serializing_if = "Option::is_none", with = "opt_date_time_format")]
    pub end_date: Option<DateTime<Utc>>,
}

/// The request body for recording the results of an automated
/// test.
///
/// See the REST `POST: projects/{project_id}/test-runs/record`
/// and the SOAP `RemoteTestRun`.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TestRun<'a> {
    /// The format of the automation results.
    pub test_run_format_id: TestRunFormatId,

    // The name of the external automated tool that executed the
    // test.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_name: Option<Cow<'a, str>>,

    /// The name of the test case as it is known in the external
    /// tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_test_name: Option<Cow<'a, str>>,

    /// The number of assertions/errors reported during the
    /// automated test execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_assert_count: Option<i32>,

    /// The summary result of the test case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_message: Option<Cow<'a, str>>,

    /// The detailed trace of test results reported back from the
    /// automated testing tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_stack_trace: Option<Cow<'a, str>>,

    /// The id of the automation host that the result is being
    /// recorded for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_host_id: Option<i32>,

    /// The id of the automation engine that the result is being
    /// recorded for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_engine_id: Option<i32>,

    /// The token of the automation engine that the result is
    /// being recorded for (read-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_engine_token: Option<Cow<'a, str>>,

    /// The id of the attachment that is being used to store the
    /// test script (file or url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_attachment_id: Option<i32>,

    /// The list of test case parameters that have been provided.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub parameters: Vec<RemoteTestSetTestCaseParameter>,

    /// The datetime the test was scheduled for.
    #[serde(skip_serializing_if = "Option::is_none", with = "opt_date_time_format")]
    pub scheduled_date: Option<DateTime<Utc>>,

    /// The list of test steps that comprise the automated test
    /// These are optional for automated test runs. The status of
    /// the test run steps does not change the overall status of
    /// the automated test run. They are used to simply make
    /// reporting clearer inside the system. They will also
    /// update the status of appropriate Test Step(s) if a valid
    /// test step id is provided.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub test_run_steps: Vec<RemoteTestRunStep>,

    /// The id of the test run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_run_id: Option<i32>,

    /// The name of the test run (usually the same as the test
    /// case).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Cow<'a, str>>,

    /// The id of the test case that the test run is an instance
    /// of.
    pub test_case_id: i32,

    /// The guid of the test case that the test run is an
    /// instance of.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_case_guid: Option<Cow<'a, str>>,

    /// The id of the type of test run (automated vs. manual).
    pub test_run_type_id: TestRunTypeId,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The id of the user that executed the test. The
    /// authenticated user is used if no value is provided.
    pub tester_id: Option<i32>,

    /// The guid of the user that executed the test.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tester_guid: Option<Cow<'a, str>>,

    /// The id of overall execution status for the test run.
    pub execution_status_id: ExecutionStatusId,

    /// The id of the release that the test run should be
    /// reported against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<i32>,

    /// The guid of the release that the test run should be
    /// reported against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_guid: Option<Cow<'a, str>>,

    /// The id of the test set that the test run should be
    /// reported against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_set_id: Option<i32>,

    /// The guid of the test set that the test run should be
    /// reported against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_set_guid: Option<Cow<'a, str>>,

    /// The id of the unique test case entry in the test set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_set_test_case_id: Option<i32>,

    /// The date/time that the test execution was started.
    #[serde(with = "date_time_format")]
    pub start_date: DateTime<Utc>,

    /// The date/time that the test execution was completed.
    #[serde(skip_serializing_if = "Option::is_none", with = "opt_date_time_format")]
    pub end_date: Option<DateTime<Utc>>,

    /// The id of the build that the test was executed against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<i32>,

    /// The estimated duration of how long the test should take
    /// to execute (read-only). This field is populated from the
    /// test case being executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_duration: Option<i32>,

    /// The actual duration of how long the test should take to
    /// execute (read-only). This field is calculated from the
    /// start/end dates provided during execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_duration: Option<Cow<'a, str>>,

    /// The id of the specific test configuration that was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_configuration_id: Option<i32>,

    /// The version number of the release the test set is
    /// scheduled for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_version_number: Option<Cow<'a, str>>,

    /// The id of the project that the artifact belongs to.
    pub project_id: i32,

    /// The guid of the project that the artifact belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_guid: Option<Cow<'a, str>>,

    /// The type of artifact.
    pub artifact_type_id: ArtifactId,

    /// The datetime used to track optimistic concurrency to
    /// prevent edit conflicts.
    #[serde(with = "date_time_format")]
    pub concurrency_date: DateTime<Utc>,

    /// The list of associated custom properties/fields for this
    /// artifact.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub custom_properties: Vec<RemoteArtifactCustomProperty>,

    /// Does this artifact have any attachments?
    #[serde(skip_serializing_if = "is_false")]
    pub is_attachments: bool,

    /// The list of meta-tags that should be associated with the
    /// artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Cow<'a, str>>,

    /// The unique identifier for the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<Cow<'a, str>>,
}
