use super::*;

mod protocol;
use crate::tests::protocol::*;

use std::fs::File;

use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};

use crate::storage::mem_storage::*;

use serde_yaml;

#[derive(Debug, PartialEq, Serialize, Deserialize)] 
enum Actions {
    Init {
        id: u64,
        policy: u64,
    },
    Command {
        id: u64,
        parent: u64,
        priority: u32,
        payload: (u64, u64),
    },
    Merge {
        id: u64,
        left: u64, 
        right: u64,
    },
    Heads(u32),
    Segments(u32),
    Orphans(u32),
    AutoMerge,
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    Client(#[from] ClientError),
    Engine(#[from] engine::EngineError),
    Io(#[from] std::io::Error),
    SerdeYaml(#[from] serde_yaml::Error),
}

fn read(file: &str) -> Result<Vec<Actions>,TestError> {
    let file = File::open(file)?;
    let actions: Vec<Actions> = serde_yaml::from_reader(file)?;
    Ok(actions)
}

fn run(file: &str) -> Result<(),TestError> {
    let mut commands = BTreeMap::new();
    let actions: Vec<Actions> = read(file)?;

    let mut provider: MemStorageProvider<TestProtocol,u64,u64> = MemStorageProvider::new();

    let mut storage_id: GraphId = 0.into();
    let mut orphans = 0;
    let policy_id = 0;
    let group_id = 0;
    for rule in actions {
        match rule {
            Actions::Init{id} => {
                let payload = (0, 0);
                let perspective = provider.new_perspective(&policy_id);
                let command_id = perspective.init(payload);
                let update = perspective.to_update();
                storage_id = provider.new_storage(&group_id, update)?;
                storage.commit(update)?;

                commands.insert(id, command_id);
            },
            Actions::Command{id, parent, priority, payload} => {
                let mapped = match commands.get(&parent) {
                    None => parent.into(),
                    Some(id) => *id,       
                };

                let storage = provider.get_storage(&storage_id)?;
                let perspective = storage.get_perspective(&parent)?;
                let command_id = perspective.extend(priority, payload);
                let update = perspective.to_update();
                storage.commit(update)?;

                commands.insert(id, command_id);
            },
            Actions::Merge{id, left, right} => {
                let mapped = match commands.get(&parent) {
                    None => parent.into(),
                    Some(id) => *id,       
                };

                let storage = provider.get_storage(&storage_id)?;
                let command_id = storage.merge(left,right)?;

                commands.insert(id, command_id);
            }
            Actions::Heads(n) => {
                let storage = provider.get_storage(&storage_id)?;
                let heads = storage.heads(&storage_id)?;
                assert_eq!(heads.len(), n as usize);
            },
            Actions::Segments(n) => {
                let storage = provider.get_storage(&storage_id)?;
                assert_eq!(storage.segments(), n );
            },
            Actions::Orphans(n) => {
                assert_eq!(orphans, n );
            },
            Actions::AutoMerge => {
                state.merge(&storage_id)?;
            },
        };
    }
    Ok(())
}

#[test]
fn new () -> Result<(),TestError> {
    run("src/tests/new.test")?;
    Ok(())
}

#[test]
fn fail_origin_check () -> Result<(),TestError> {
    run("src/tests/fail_origin_check.test")?;
    Ok(())
}

#[test]
fn missing_parent () -> Result<(),TestError> {
    run("src/tests/missing_parent.test")?;
    Ok(())
}

#[test]
fn branch () -> Result<(),TestError> {
    run("src/tests/branch.test")?;
    Ok(())
}

#[test]
fn merge () -> Result<(),TestError> {
    run("src/tests/merge.test")?;
    Ok(())
}

#[test]
fn split () -> Result<(),TestError> {
    run("src/tests/split.test")?;
    Ok(())
}

#[test]
fn merge_split () -> Result<(),TestError> {
    run("src/tests/merge_split.test")?;
    Ok(())
}


#[test]
fn do_merge2 () -> Result<(),TestError> {
    run("src/tests/do_merge2.test")?;
    Ok(())
}

#[test]
fn do_merge3 () -> Result<(),TestError> {
    run("src/tests/do_merge3.test")?;
    Ok(())
}

#[test]
fn do_merge2_extend_merge () -> Result<(),TestError> {
    run("src/tests/do_merge2_extend_merge.test")?;
    Ok(())
}


