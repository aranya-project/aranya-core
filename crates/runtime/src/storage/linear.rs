use super::*;

struct CommandIndex {
    cut: u64,
    id: Id,
    priority: u32,
    parent: Parent,
    index: usize,
    len: usize,
}

struct SegmentInfo {
    start: usize,
    end: usize,
}

pub struct LinearStorage<T, K, V>
where
    T: Command,
{
    facts: Vec<MemStoragePerspective<K, V>>,
    backing: Vec<u8>,
    index: Vec<CommandIndex>,
    segments: Vec<SegmentInfo>,
    commands: Vec<T>,
}

impl<T, K, V> LinearStorage<T, K, V>
where
    T: Command,
{
    pub fn new() -> Self {
        let facts = vec![LinearStoragePerspective::new()];
        let commands = Vec::new();
        LinearStorage { facts, commands }
    }
}

impl<T, K, V> Storage<T, K, V> for LinearStorage<T, K, V>
where
    K: Ord + Clone,
    V: Clone,
    T: Command,
{
    type Perspective = LinearStoragePerspective<K, V>;

    fn get_perspective_mut<'a>(&'a mut self, command: &T) -> &'a mut Self::Perspective {
        &mut self.facts[0]
    }

    fn get_segment_mut<'a>(&'a mut self, id: Id) -> &'a mut Segment<T> {
        unimplemented!()
    }
}

enum Update<K, V> {
    Delete(K),
    Insert(K, V),
}

pub struct LinearStoragePerspective<K, V> {
    facts: BTreeMap<K, Option<V>>,
    location: Vec<Location>,
    temp: BTreeMap<K, Option<V>>,
    updates: Vec<Update<K, V>>,
}

impl<K, V> LinearStoragePerspective<K, V> {
    pub fn new() -> Self {
        LinearStoragePerspective {
            facts: BTreeMap::new(),
            location: Vec::new(),
            temp: BTreeMap::new(),
            updates: Vec::new(),
        }
    }
}

impl<K, V> Perspective<K, V> for LinearStoragePerspective<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    fn get<'a>(&'a self, key: &K) -> Option<&'a V> {
        match self.temp.get(key) {
            Some(wrapped) => wrapped.as_ref(),
            None => match self.facts.get(key) {
                None => None,
                Some(wrapped) => wrapped.as_ref(),
            },
        }
    }

    fn insert(&mut self, key: K, value: V) {
        self.temp.insert(key.clone(), Some(value.clone()));
        self.updates.push(Update::Insert(key, value));
    }

    fn delete(&mut self, key: K) {
        self.temp.insert(key.clone(), None);
        self.updates.push(Update::Delete(key));
    }

    fn revert(&mut self) {
        self.temp.clear();
        self.updates.clear();
    }

    fn commit(&mut self, location: Vec<Location>) {
        self.location = location;
        for update in self.updates.drain(0..) {
            match update {
                Update::Delete(key) => {
                    self.facts.insert(key, None);
                }
                Update::Insert(key, value) => {
                    self.facts.insert(key, Some(value));
                }
            }
        }

        self.revert();
    }
}
