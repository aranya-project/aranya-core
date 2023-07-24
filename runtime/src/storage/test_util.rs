use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json;
use std::{error::Error, fs::File, io::BufReader, path::PathBuf};

use crate::command::{Command, Id, Parent, Priority};
use crate::engine::PolicyId;
use crate::storage::{Location, Perspective, Segment, Storage, StorageError, StorageProvider};

pub(super) static TEST_POLICY: Option<[u8; 32]> = Some([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1,
]);

// Validate a storage provider has the expected properties
pub(super) fn validate_state(provider: &mut impl StorageProvider, group_id: &Id, expect: StateLog) {
    let storage = provider
        .get_storage(group_id)
        .expect("Failed to get storage {group_id}");
    let current_head_count = storage
        .get_heads()
        .expect("Failed to get graph {group_id} heads")
        .len();

    // Validate storage is tracking branches correctly
    assert_eq!(
        expect.heads, current_head_count,
        "Expected {} heads but state reports {}",
        expect.heads, current_head_count
    );

    let location = Location::new(expect.segment_index, expect.command_index);
    // Asserts the expected segment exists
    let segment = storage
        .get_segment(&location)
        .expect("Failed to get segment {expect.segment_index}");

    // Validate the stored command exists in the expected memory segment
    assert_eq!(
        expect.segment_index,
        segment.index(),
        "Expected segment index {} but state reports {}",
        expect.segment_index,
        segment.index()
    );
    // Validate the segment has the expected maximum cut
    assert_eq!(
        expect.max_cut,
        segment.max_cut(),
        "Expected max cut {:?} but state reports {:?}",
        expect.max_cut,
        segment.max_cut()
    );

    let (expect_key, expect_value) = (expect.fact.key, expect.fact.value);
    // Asserts the command is stored in state
    let stored_command = segment.get_command(&location).unwrap_or_else(|| {
        panic!(
            "{}",
            &format!("Command {:?} wasn't found", location.command)
        )
    });
    // Retrieve a perspective of the graph from the most recent command,
    // and panic if this perspective is not retrievable
    let perspective = storage
        .get_perspective(&stored_command.id())
        .expect("Failed to get perspective")
        .unwrap_or_else(|| {
            panic!(
                "{}",
                &format!("Perspective {:?} does not exist", stored_command.id())
            )
        });
    // Attempt to fetch the expected fact
    let query_result = perspective
        .query(&expect_key)
        .unwrap_or_else(|_| {
            panic!(
                "{}",
                &format!(
                    "Failed to query factdb from {:?} perspective",
                    stored_command.id()
                )
            )
        })
        .map(|v| v.to_vec());

    // Validate the expected fact value is stored in state
    assert_eq!(
        expect_value.map(|v| v.to_vec()),
        query_result,
        "Expected fact value {:?} but state reports {:?}",
        expect_value,
        query_result,
    );
}

#[derive(Deserialize)]
pub(super) struct StateDelta {
    // Basic data that can be manipulated into a command
    pub command: TestCommand,
    // Information used to validate state
    #[serde(flatten)]
    pub expect: StateLog,
}

// Data used to construct a Command-implementing object
#[derive(Deserialize)]
pub(super) struct TestCommand {
    pub priority: Priority,
    pub id: Id,
    pub parent: Parent,
}

// Debug runtime storage. May be replaced by a logging trait
// in the future.
//
// Values, independent of implementation, to inform the test
// of how storage internals are expected to be structured.
#[derive(Deserialize)]
pub(super) struct StateLog {
    // Index of the segment storing the associated command
    segment_index: usize,
    // Index of the command within its segment
    command_index: usize,
    // Maximum number of steps between the graph root and the command
    max_cut: usize,
    // Number of branch heads in the parent graph
    heads: usize,
    // Key-value pair associated to the command that should be accessible
    // in state
    #[serde(flatten)]
    fact: TestFact,
}

// Represents a fact, associated with a specific command
#[derive(Deserialize)]
pub(super) struct TestFact {
    key: [u8; 16],
    value: Option<[u8; 16]>,
}

// Process a linear list of tuples, each of which contains a command and
// expected state properties used to validate the storage implementation
// once the command has been committed.
pub(super) fn run(
    provider: &mut impl StorageProvider,
    test_data: Vec<(impl Command, StateLog)>,
) -> Result<()> {
    // Save ID for this graph's storage (ID of the init command)
    let group_id = test_data
        .first()
        .context("No commands supplied to test")?
        .0
        .id();
    // Iterate over commands to be stored and validate state once committed
    for (command, expect) in test_data {
        match command.parent() {
            Parent::None => {
                // As there is no parent, we need to generate a new perspective
                let mut init_perspective = provider.new_perspective(&PolicyId::new(0));
                // Check if the fact should be inserted or deleted
                match expect.fact.value {
                    Some(b) => init_perspective.insert(&expect.fact.key, &b),
                    None => init_perspective.delete(&expect.fact.key),
                }
                // Add the init command to the new perspective
                let _ = init_perspective
                    .add_command(&command)
                    .context("Failed to add command {command.id().into()}")?;
                let update = init_perspective.to_update();
                // Create a new graph using the initial command
                let _ = provider
                    .new_storage(&group_id, update)
                    .context("Failed to create new storage {group_id}")?;
                validate_state(provider, &group_id, expect);
            }
            Parent::Id(parent) => {
                // Store the parent Id to retrieve a perspective of the graph
                let perspective_id = &parent;
                // Use the init command's Id to retrieve the graph from state
                let storage = provider
                    .get_storage(&group_id)
                    .context("Failed to get storage {group_id}")?;
                // Validate that the storage can produce a perspective of the
                // graph from the parent of the command to be committed
                let mut perspective = {
                    let opt = storage
                        .get_perspective(perspective_id)
                        .context("Failed to get perspective {storage_id}")?;
                    assert!(opt.is_some());
                    opt.unwrap()
                };
                // Check if the fact should be inserted or deleted
                match expect.fact.value {
                    Some(b) => perspective.insert(&expect.fact.key, &b),
                    None => perspective.delete(&expect.fact.key),
                }
                // Add the provided command to the retrieved perspective
                let _ = perspective
                    .add_command(&command)
                    .context("Failed to add command {command.id().into()}")?;
                // Convert the perspective to an update that can be committed
                let update = perspective.to_update();
                // Commit the update, containing the new fact and command
                storage
                    .commit(update)
                    .context("Failed to commit update for command {command.id().into()}")?;
                validate_state(provider, &group_id, expect);
            }
            Parent::Merge(_left_parent, _) => {
                unimplemented!();
            }
        }
    }

    Ok(())
}

// Load a file containing JSON that can be converted to usable test data
pub(super) fn load_test_file(file_name: &str) -> Result<Vec<StateDelta>> {
    // Construct the path to the test file
    // First, grab the directory containing this crate's manifest
    let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Add path to JSON test files within the runtime crate
    path_buf.push(format!("src/storage/test_data/{}.json", file_name));

    // Open the file in read-only mode with buffer.
    let file = File::open(path_buf.as_path())?;
    let reader = BufReader::new(file);
    // Convert JSON to a list of `StateDelta` objects, which contain
    // generic test data that is not specific to any implementation.
    let deltas: Vec<StateDelta> = serde_json::from_reader(reader)?;

    Ok(deltas)
}

// Build storage tests dynamically.
//
// The first two arguments are provided inside of a tuple and determine the
// storage implementation that will run the test. The last argument may be
// one or more file names that can be deserialized into data used by tests.
//
// # Arguments
//
// * `$provider:expr`: An expression that evaluates to an implementation
//  of the `StorageProvider` trait.
// * `$command_type:ident`: Identifies the `Command` implementation that will
//  be used by the generated tests. The implementation must implement
//  `From<TestCommand>` to use this macro.
// * `$( $name:ident, )`: Comma-separated list of file names that contain unique
//  data necessary to run separate tests. These identifiers are also used to name
//  generated tests.
#[macro_export]
macro_rules! create_storage_tests {
    (
        ($provider:expr, $command_type:ident)
        $( $name:ident, )+
    ) => {
    $(
        #[test]
        fn $name() {
            // Deserialize JSON into testable data
            let json_commands: Vec<StateDelta> = load_test_file(stringify!($name)).expect("Failed to load JSON commands");
            // Convert list of commands to specific implementation that invoked
            // the test
            let test_commands: Vec<($command_type, StateLog)> = json_commands.into_iter().map(|test_data| {
                let command_impl = $command_type::from(test_data.command);
                (command_impl, test_data.expect)
            }).collect::<Vec<(_, _)>>();

            if let Err(err) = run(&mut $provider, test_commands) {
                panic!("{} failed to run: {err}", stringify!($name));
            }
        }
    )+
    };
}

// Make this macro publicly accessible in the parent module, `storage`
pub(super) use create_storage_tests;

// Implement the std crate's Error trait in order to add context to errors
// that may occur during tests. The `anyhow` crate requires this trait is
// implemented in order to use the `context` method when unwrapping results.
impl Error for StorageError {}
