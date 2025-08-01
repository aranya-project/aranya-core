macro_rules! typed_interner {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($ty:ty) => $id:ident;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Default, Debug, ::serde::Serialize, ::serde::Deserialize)]
        $vis struct $name {
            items: ::indexmap::IndexSet<$ty>,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    items: ::indexmap::IndexSet::new(),
                }
            }

            pub fn intern(&mut self, item: $ty) -> $id {
                if let Some(idx) = self.items.get_index_of(&item) {
                    return $id(idx.try_into().unwrap());
                }
                let (idx, _) = self.items.insert_full(item);
                $id(idx.try_into().unwrap())
            }

            pub fn get(&self, id: $id) -> Option<&$ty> {
                self.items.get_index(id.0 as usize)
            }
        }

        #[derive(
            Copy,
            Clone,
            Default,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            std::hash::Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        $vis struct $id(u32);
    };
}
pub(crate) use typed_interner;
