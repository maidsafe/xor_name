// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Container that acts as a map whose keys are prefixes.

use crate::{Prefix, XorName};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::{btree_map, BTreeMap},
};

/// Container that acts as a map whose keys are prefixes.
///
/// It differs from a normal map of `Prefix` -> `T` in a couple of ways:
/// 1. It allows to keep the prefix and the value in the same type which makes it internally more
///    similar to a set of `(Prefix, T)` rather than map of `Prefix` -> `T` while still providing
///    convenient map-like API
/// 2. It automatically prunes redundant entries. That is, when the prefix of an entry is fully
///    covered by other prefixes, that entry is removed. For example, when there is entry with
///    prefix (00) and we insert entries with (000) and (001), the (00) prefix becomes fully
///    covered and is automatically removed.
///
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(missing_debug_implementations)]
#[serde(transparent)]
pub struct PrefixMap<T>(BTreeMap<Prefix, T>)
where
    T: Borrow<Prefix>;

impl<T> PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    /// Create empty `PrefixMap`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts new entry into the map. Replaces previous entry at the same prefix.
    /// Removes those ancestors of the inserted prefix that are now fully covered by their
    /// descendants.
    /// Does not insert anything if any descendant of the prefix of `entry` is already present in
    /// the map.
    /// Returns a boolean indicating whether anything changed.
    pub fn insert(&mut self, entry: T) -> bool {
        // Don't insert if any descendant is already present in the map.
        if self.descendants(entry.borrow()).next().is_some() {
            return false;
        }

        let prefix = entry.borrow().clone();
        let _ = self.0.insert(prefix, entry);

        let parent_prefix = prefix.popped();
        self.prune(parent_prefix);
        true
    }

    /// Get the entry at `prefix`, if any.
    pub fn get(&self, prefix: &Prefix) -> Option<&T> {
        self.0.get(prefix)
    }

    /// Get the entry at the prefix that matches `name`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub fn get_matching(&self, name: &XorName) -> Option<&T> {
        self.0
            .iter()
            .filter(|(prefix, _)| prefix.matches(name))
            .max_by_key(|(prefix, _)| prefix.bit_count())
            .map(|(_, entry)| entry)
    }

    /// Get the entry at the prefix that matches `prefix`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub fn get_matching_prefix(&self, prefix: &Prefix) -> Option<&T> {
        self.get_matching(&prefix.name())
    }

    /// Returns an iterator over the entries, in order by prefixes.
    // TODO check if really ordered
    pub fn iter(&self) -> impl Iterator<Item = &T> + Clone {
        self.0.iter().map(|(_, entry)| entry)
    }

    /// Returns an iterator over all entries whose prefixes are descendants (extensions) of
    /// `prefix`.
    pub fn descendants<'a>(
        &'a self,
        prefix: &'a Prefix,
    ) -> impl Iterator<Item = &'a T> + Clone + 'a {
        // TODO: there might be a way to do this in O(logn) using BTreeMap::range
        // self.0
        //     .range(prefix..)
        self.0
            .iter()
            .filter(move |(p, _)| p.is_extension_of(prefix))
            .map(|(_, entry)| entry)
    }

    /// Remove `prefix` and any of its ancestors if they are covered by their descendants.
    /// For example, if `(00)` and `(01)` are both in the map, we can remove `(0)` and `()`.
    pub fn prune(&mut self, mut prefix: Prefix) {
        // TODO: can this be optimized?

        loop {
            if prefix.is_covered_by(self.descendants(&prefix).map(|entry| entry.borrow())) {
                let _ = self.0.remove(&prefix);
            }

            if prefix.is_empty() {
                break;
            } else {
                prefix = prefix.popped();
            }
        }
    }
}

// We have to impl this manually since the derive would require T: Default, which is not necessary.
// See rust-lang/rust#26925
impl<T> Default for PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    fn default() -> Self {
        Self(Default::default())
    }
}

// Need to impl this manually, because the derived one would use `PartialEq` of `Entry` which
// compares only the prefixes.
impl<T> PartialEq for PrefixMap<T>
where
    T: Borrow<Prefix> + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(lhs, rhs)| lhs.0 == rhs.0)
    }
}

impl<T> Eq for PrefixMap<T> where T: Borrow<Prefix> + Eq {}

impl<T> From<PrefixMap<T>> for BTreeMap<Prefix, T>
where
    T: Borrow<Prefix> + Ord,
{
    fn from(map: PrefixMap<T>) -> Self {
        map.0
    }
}

impl<T> IntoIterator for PrefixMap<T>
where
    T: Borrow<Prefix>,
{
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

/// An owning iterator over the values of a [`PrefixMap`].
///
/// This struct is created by [`PrefixMap::into_iter`].
#[derive(Debug)]
pub struct IntoIter<T>(btree_map::IntoIter<Prefix, T>);

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, entry)| entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use eyre::Result;

    #[test]
    fn insert_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert((prefix("0"), 1)), true);
        assert_eq!(map.insert((prefix("0"), 2)), true);
        assert_eq!(map.get(&prefix("0")), Some(&(prefix("0"), 2)));
    }

    #[test]
    fn insert_direct_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert((prefix("0"), 0)), true);

        // Insert the first sibling. Parent remain in the map.
        assert_eq!(map.insert((prefix("00"), 1)), true);
        assert_eq!(map.get(&prefix("00")), Some(&(prefix("00"), 1)));
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&(prefix("0"), 0)));

        // Insert the other sibling. Parent is removed because it is now fully covered by its
        // descendants.
        assert_eq!(map.insert((prefix("01"), 2)), true);
        assert_eq!(map.get(&prefix("00")), Some(&(prefix("00"), 1)));
        assert_eq!(map.get(&prefix("01")), Some(&(prefix("01"), 2)));
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_indirect_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert_eq!(map.insert((prefix("0"), 0)), true);

        assert_eq!(map.insert((prefix("000"), 1)), true);
        assert_eq!(map.get(&prefix("000")), Some(&(prefix("000"), 1)));
        assert_eq!(map.get(&prefix("001")), None);
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&(prefix("0"), 0)));

        assert_eq!(map.insert((prefix("001"), 2)), true);
        assert_eq!(map.get(&prefix("000")), Some(&(prefix("000"), 1)));
        assert_eq!(map.get(&prefix("001")), Some(&(prefix("001"), 2)));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some(&(prefix("0"), 0)));

        assert_eq!(map.insert((prefix("01"), 3)), true);
        assert_eq!(map.get(&prefix("000")), Some(&(prefix("000"), 1)));
        assert_eq!(map.get(&prefix("001")), Some(&(prefix("001"), 2)));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), Some(&(prefix("01"), 3)));
        // (0) is now fully covered and so was removed
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_ancestor_of_existing_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert((prefix("00"), 1));

        assert_eq!(map.insert((prefix("0"), 2)), false);
        assert_eq!(map.get(&prefix("0")), None);
        assert_eq!(map.get(&prefix("00")), Some(&(prefix("00"), 1)));
    }

    #[test]
    fn get_matching() {
        let mut rng = rand::thread_rng();

        let mut map = PrefixMap::new();
        let _ = map.insert((prefix("0"), 0));
        let _ = map.insert((prefix("1"), 1));
        let _ = map.insert((prefix("10"), 10));

        assert_eq!(
            map.get_matching(&prefix("0").substituted_in(rng.gen())),
            Some(&(prefix("0"), 0))
        );

        assert_eq!(
            map.get_matching(&prefix("11").substituted_in(rng.gen())),
            Some(&(prefix("1"), 1))
        );

        assert_eq!(
            map.get_matching(&prefix("10").substituted_in(rng.gen())),
            Some(&(prefix("10"), 10))
        );
    }

    #[test]
    fn get_matching_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert((prefix("0"), 0));
        let _ = map.insert((prefix("1"), 1));
        let _ = map.insert((prefix("10"), 10));

        assert_eq!(
            map.get_matching_prefix(&prefix("0")),
            Some(&(prefix("0"), 0))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("11")),
            Some(&(prefix("1"), 1))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("10")),
            Some(&(prefix("10"), 10))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("101")),
            Some(&(prefix("10"), 10))
        );
    }

    #[test]
    fn serialize_transparent() -> Result<()> {
        let mut map = PrefixMap::new();
        let _ = map.insert((prefix("0"), 0));
        let _ = map.insert((prefix("1"), 1));
        let _ = map.insert((prefix("10"), 10));

        let copy_map: BTreeMap<_, _> = map.clone().0.into_iter().collect();
        let serialized_copy_map = rmp_serde::to_vec(&copy_map)?;

        assert_eq!(rmp_serde::to_vec(&map)?, serialized_copy_map);
        let _ = rmp_serde::from_read::<_, PrefixMap<(Prefix, i32)>>(&*serialized_copy_map)?;
        Ok(())
    }

    fn prefix(s: &str) -> Prefix {
        s.parse().expect("")
    }
}
