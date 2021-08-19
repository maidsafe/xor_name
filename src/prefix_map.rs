// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Container that acts as a map whose keys are Prefixes.

use crate::{Prefix, XorName};
// use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::RwLock;

/// Container that acts as a map whose keys are prefixes.
///
/// It automatically prunes redundant entries. That is, when the prefix of an entry is fully
/// covered by other prefixes, that entry is removed. For example, when there is entry with
/// prefix (00) and we insert entries with (000) and (001), the (00) prefix becomes fully
/// covered and is automatically removed.
///
pub struct PrefixMap<T>(RwLock<BTreeMap<Prefix, T>>);

impl<T> PrefixMap<T>
where
    T: Clone,
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
    pub async fn insert(&mut self, prefix: Prefix, entry: T) -> bool {
        // Don't insert if any descendant is already present in the map.
        // TODO: there might be a way to do this in O(logn) using BTreeMap::range
        let exist_any_descendants = {
            let rlock = self.0.read().await;
            rlock.iter().any(move |(p, _)| p.is_extension_of(&prefix))
        };
        if exist_any_descendants {
            return false;
        }

        {
            let mut wlock = self.0.write().await;
            let _ = wlock.insert(prefix, entry);
        }

        let parent_prefix = prefix.popped();
        self.prune(parent_prefix).await;
        true
    }

    /// Get the entry at `prefix`, if any.
    pub async fn get(&self, prefix: &Prefix) -> Option<(Prefix, T)> {
        let rlock = self.0.read().await;
        rlock.get_key_value(prefix).map(|(p, t)| (*p, t.clone()))
    }

    /// Get the entry at the prefix that matches `name`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub async fn get_matching(&self, name: &XorName) -> Option<(Prefix, T)> {
        let rlock = self.0.read().await;
        rlock
            .iter()
            .filter(|(prefix, _)| prefix.matches(name))
            .max_by_key(|(prefix, _)| prefix.bit_count())
            .map(|(p, t)| (*p, t.clone()))
    }

    /// Get the entry at the prefix that matches `prefix`. In case of multiple matches, returns the
    /// one with the longest prefix.
    pub async fn get_matching_prefix(&self, prefix: &Prefix) -> Option<(Prefix, T)> {
        self.get_matching(&prefix.name()).await
    }

    /// Remove `prefix` and any of its ancestors if they are covered by their descendants.
    /// For example, if `(00)` and `(01)` are both in the map, we can remove `(0)` and `()`.
    pub async fn prune(&mut self, mut prefix: Prefix) {
        // TODO: can this be optimized?

        loop {
            let can_remove = {
                let rlock = self.0.read().await;
                let descendant_prefixes = rlock
                    .iter()
                    .filter(move |(p, _)| p.is_extension_of(&prefix))
                    .map(|(prefix, _)| prefix);
                prefix.is_covered_by(descendant_prefixes)
            };
            if can_remove {
                let mut wlock = self.0.write().await;
                let _ = wlock.remove(&prefix);
            }

            if prefix.is_empty() {
                break;
            } else {
                prefix = prefix.popped();
            }
        }
    }
}

impl<T> Default for PrefixMap<T> {
    fn default() -> Self {
        PrefixMap(RwLock::new(BTreeMap::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;
    use rand::Rng;

    #[test]
    fn insert_existing_prefix() {
        let mut map = PrefixMap::new();
        assert!(map.insert(prefix("0"), 1));
        assert!(map.insert(prefix("0"), 2));
        assert_eq!(map.get(&prefix("0")), Some((&prefix("0"), &2)));
    }

    #[test]
    fn test_eq() {
        let mut map = PrefixMap::new();
        assert!(map.insert(prefix("0"), 1));
        assert!(map.insert(prefix("01"), 2));
        let mut map2 = PrefixMap::new();
        assert!(map2.insert(prefix("0"), 1));
        assert!(map2.insert(prefix("01"), 2));
        assert_eq!(map, map2);

        let mut map3 = PrefixMap::new();
        assert!(map3.insert(prefix("0"), 1));
        assert!(map3.insert(prefix("01"), 3));
        assert_ne!(map, map3);

        let mut map4 = PrefixMap::new();
        assert!(map4.insert(prefix("0"), 1));
        assert!(map4.insert(prefix("00"), 2));
        assert_ne!(map, map4);
    }

    #[test]
    fn insert_direct_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert!(map.insert(prefix("0"), 0));

        // Insert the first sibling. Parent remain in the map.
        assert!(map.insert(prefix("00"), 1));
        assert_eq!(map.get(&prefix("00")), Some((&prefix("00"), &1)));
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some((&prefix("0"), &0)));

        // Insert the other sibling. Parent is removed because it is now fully covered by its
        // descendants.
        assert!(map.insert(prefix("01"), 2));
        assert_eq!(map.get(&prefix("00")), Some((&prefix("00"), &1)));
        assert_eq!(map.get(&prefix("01")), Some((&prefix("01"), &2)));
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_indirect_descendants_of_existing_prefix() {
        let mut map = PrefixMap::new();
        assert!(map.insert(prefix("0"), 0));

        assert!(map.insert(prefix("000"), 1));
        assert_eq!(map.get(&prefix("000")), Some((&prefix("000"), &1)));
        assert_eq!(map.get(&prefix("001")), None);
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some((&prefix("0"), &0)));

        assert!(map.insert(prefix("001"), 2));
        assert_eq!(map.get(&prefix("000")), Some((&prefix("000"), &1)));
        assert_eq!(map.get(&prefix("001")), Some((&prefix("001"), &2)));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), None);
        assert_eq!(map.get(&prefix("0")), Some((&prefix("0"), &0)));

        assert!(map.insert(prefix("01"), 3));
        assert_eq!(map.get(&prefix("000")), Some((&prefix("000"), &1)));
        assert_eq!(map.get(&prefix("001")), Some((&prefix("001"), &2)));
        assert_eq!(map.get(&prefix("00")), None);
        assert_eq!(map.get(&prefix("01")), Some((&prefix("01"), &3)));
        // (0) is now fully covered and so was removed
        assert_eq!(map.get(&prefix("0")), None);
    }

    #[test]
    fn insert_ancestor_of_existing_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("00"), 1);

        assert!(!map.insert(prefix("0"), 2));
        assert_eq!(map.get(&prefix("0")), None);
        assert_eq!(map.get(&prefix("00")), Some((&prefix("00"), &1)));
    }

    #[test]
    fn get_matching() {
        let mut rng = rand::thread_rng();

        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("0"), 0);
        let _ = map.insert(prefix("1"), 1);
        let _ = map.insert(prefix("10"), 10);

        assert_eq!(
            map.get_matching(&prefix("0").substituted_in(rng.gen())),
            Some((&prefix("0"), &0))
        );

        assert_eq!(
            map.get_matching(&prefix("11").substituted_in(rng.gen())),
            Some((&prefix("1"), &1))
        );

        assert_eq!(
            map.get_matching(&prefix("10").substituted_in(rng.gen())),
            Some((&prefix("10"), &10))
        );
    }

    #[test]
    fn get_matching_prefix() {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("0"), 0);
        let _ = map.insert(prefix("1"), 1);
        let _ = map.insert(prefix("10"), 10);

        assert_eq!(
            map.get_matching_prefix(&prefix("0")),
            Some((&prefix("0"), &0))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("11")),
            Some((&prefix("1"), &1))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("10")),
            Some((&prefix("10"), &10))
        );

        assert_eq!(
            map.get_matching_prefix(&prefix("101")),
            Some((&prefix("10"), &10))
        );
    }

    #[test]
    fn serialize_transparent() -> Result<()> {
        let mut map = PrefixMap::new();
        let _ = map.insert(prefix("0"), 0);
        let _ = map.insert(prefix("1"), 1);
        let _ = map.insert(prefix("10"), 10);

        let copy_map: BTreeMap<_, _> = map.clone().into();
        let serialized_copy_map = rmp_serde::to_vec(&copy_map)?;

        assert_eq!(rmp_serde::to_vec(&map)?, serialized_copy_map);
        let _ = rmp_serde::from_read::<_, PrefixMap<i32>>(&*serialized_copy_map)?;
        Ok(())
    }

    fn prefix(s: &str) -> Prefix {
        s.parse().expect("")
    }
}
