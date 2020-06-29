// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{XorName, XOR_NAME_LEN};
use core::{
    borrow::Borrow,
    cmp::{self, Ordering},
    fmt::{Binary, Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::RangeInclusive,
    str::FromStr,
};
use serde::{Deserialize, Serialize};

/// A section prefix, i.e. a sequence of bits specifying the part of the network's name space
/// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Deserialize, Serialize)]
pub struct Prefix {
    bit_count: u16,
    name: XorName,
}

impl Prefix {
    /// Creates a new `Prefix` with the first `bit_count` bits of `name`. Insignificant bits are all
    /// set to 0.
    pub fn new(bit_count: usize, name: XorName) -> Self {
        Prefix {
            bit_count: bit_count.min(8 * XOR_NAME_LEN) as u16,
            name: name.set_remaining(bit_count as u8, false),
        }
    }

    /// Returns the name of this prefix.
    pub fn name(&self) -> XorName {
        self.name
    }

    /// Returns `self` with an appended bit: `0` if `bit` is `false`, and `1` if `bit` is `true`. If
    /// `self.bit_count` is already at the maximum for this type, then an unmodified copy of `self`
    /// is returned.
    pub fn pushed(mut self, bit: bool) -> Self {
        if self.bit_count < 8 * XOR_NAME_LEN as u16 {
            self.name = self.name.with_bit(self.bit_count() as u8, bit);
            self.bit_count += 1;
        }

        self
    }

    /// Returns a prefix copying the first `bitcount() - 1` bits from `self`,
    /// or `self` if it is already empty.
    pub fn popped(mut self) -> Self {
        if self.bit_count > 0 {
            self.bit_count -= 1;
            // unused bits should be zero:
            self.name = self.name.with_bit(self.bit_count() as u8, false);
        }
        self
    }

    /// Returns the number of bits in the prefix.
    pub fn bit_count(&self) -> usize {
        self.bit_count as usize
    }

    /// Returns `true` if this is the empty prefix, with no bits.
    pub fn is_empty(&self) -> bool {
        self.bit_count == 0
    }

    /// Returns `true` if `self` is a prefix of `other` or vice versa.
    pub fn is_compatible(&self, other: &Self) -> bool {
        let i = self.name.common_prefix(&other.name);
        i >= self.bit_count() || i >= other.bit_count()
    }

    /// Returns `true` if `other` is compatible but strictly shorter than `self`.
    pub fn is_extension_of(&self, other: &Self) -> bool {
        let i = self.name.common_prefix(&other.name);
        i >= other.bit_count() && self.bit_count() > other.bit_count()
    }

    /// Returns `true` if the `other` prefix differs in exactly one bit from this one.
    pub fn is_neighbour(&self, other: &Self) -> bool {
        let i = self.name.common_prefix(&other.name);
        if i >= self.bit_count() || i >= other.bit_count() {
            false
        } else {
            let j = self
                .name
                .with_flipped_bit(i as u8)
                .common_prefix(&other.name);
            j >= self.bit_count() || j >= other.bit_count()
        }
    }

    /// Returns the number of common leading bits with the input name, capped with prefix length.
    pub fn common_prefix(&self, name: &XorName) -> usize {
        cmp::min(self.bit_count(), self.name.common_prefix(name))
    }

    /// Returns `true` if this is a prefix of the given `name`.
    pub fn matches(&self, name: &XorName) -> bool {
        self.name.common_prefix(name) >= self.bit_count()
    }

    /// Compares the distance of `self` and `other` to `target`. Returns `Less` if `self` is closer,
    /// `Greater` if `other` is closer, and compares the prefix directly if of equal distance
    /// (this is to make sorting deterministic).
    pub fn cmp_distance(&self, other: &Self, target: &XorName) -> Ordering {
        if self.is_compatible(other) {
            // Note that if bit_counts are equal, prefixes are also equal since
            // one is a prefix of the other (is_compatible).
            Ord::cmp(&self.bit_count, &other.bit_count)
        } else {
            Ord::cmp(
                &other.name.common_prefix(target),
                &self.name.common_prefix(target),
            )
        }
    }

    /// Compares the prefixes using breadth-first order. That is, shorter prefixes are ordered
    /// before longer. This is in contrast with the default `Ord` impl of `Prefix` which uses
    /// depth-first order.
    pub fn cmp_breadth_first(&self, other: &Self) -> Ordering {
        self.bit_count
            .cmp(&other.bit_count)
            .then_with(|| self.name.cmp(&other.name))
    }

    /// Returns the smallest name matching the prefix
    pub fn lower_bound(&self) -> XorName {
        if self.bit_count() < 8 * XOR_NAME_LEN {
            self.name.set_remaining(self.bit_count() as u8, false)
        } else {
            self.name
        }
    }

    /// Returns the largest name matching the prefix
    pub fn upper_bound(&self) -> XorName {
        if self.bit_count() < 8 * XOR_NAME_LEN {
            self.name.set_remaining(self.bit_count() as u8, true)
        } else {
            self.name
        }
    }

    /// Inclusive range from lower_bound to upper_bound
    pub fn range_inclusive(&self) -> RangeInclusive<XorName> {
        RangeInclusive::new(self.lower_bound(), self.upper_bound())
    }

    /// Returns whether the namespace defined by `self` is covered by prefixes in the `prefixes`
    /// set
    pub fn is_covered_by<'a, I>(&self, prefixes: I) -> bool
    where
        I: IntoIterator<Item = &'a Self> + Clone,
    {
        let max_prefix_len = prefixes
            .clone()
            .into_iter()
            .map(Self::bit_count)
            .max()
            .unwrap_or(0);
        self.is_covered_by_impl(prefixes, max_prefix_len)
    }

    fn is_covered_by_impl<'a, I>(&self, prefixes: I, max_prefix_len: usize) -> bool
    where
        I: IntoIterator<Item = &'a Self> + Clone,
    {
        prefixes
            .clone()
            .into_iter()
            .any(|x| x.is_compatible(self) && x.bit_count() <= self.bit_count())
            || (self.bit_count() <= max_prefix_len
                && self
                    .pushed(false)
                    .is_covered_by_impl(prefixes.clone(), max_prefix_len)
                && self
                    .pushed(true)
                    .is_covered_by_impl(prefixes, max_prefix_len))
    }

    /// Returns the neighbouring prefix differing in the `i`-th bit
    /// If `i` is larger than our bit count, `self` is returned
    pub fn with_flipped_bit(&self, i: u8) -> Self {
        if i as usize >= self.bit_count() {
            *self
        } else {
            Self::new(self.bit_count(), self.name.with_flipped_bit(i))
        }
    }

    /// Returns the given `name` with first bits replaced by `self`
    pub fn substituted_in(&self, mut name: XorName) -> XorName {
        // TODO: is there a more efficient way of doing that?
        for i in 0..self.bit_count() {
            name = name.with_bit(i as u8, self.name.bit(i as u8));
        }
        name
    }

    /// Returns the same prefix, with the last bit flipped, or unchanged, if empty.
    pub fn sibling(&self) -> Self {
        if self.bit_count() > 0 && self.bit_count() < 8 * XOR_NAME_LEN {
            self.with_flipped_bit(self.bit_count() as u8 - 1)
        } else {
            *self
        }
    }

    /// Returns the ancestors of this prefix that has the given bit count.
    ///
    /// # Panics
    ///
    /// Panics if `bit_count` is not less than the bit count of this prefix.
    pub fn ancestor(&self, bit_count: u8) -> Self {
        assert!((bit_count as usize) < self.bit_count());
        Self::new(bit_count as usize, self.name)
    }

    /// Returns an iterator that yields all ancestors of this prefix.
    pub fn ancestors(&self) -> Ancestors {
        Ancestors {
            target: *self,
            current_len: 0,
        }
    }
}

impl PartialEq for Prefix {
    fn eq(&self, other: &Self) -> bool {
        self.is_compatible(other) && self.bit_count == other.bit_count
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else if self.is_compatible(other) {
            self.bit_count().cmp(&other.bit_count())
        } else {
            self.name.cmp(&other.name)
        }
    }
}

impl Hash for Prefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.bit_count() {
            self.name.bit(i as u8).hash(state);
        }
    }
}

impl Binary for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "{0:1$b}", self.name, self.bit_count())
    }
}

impl Debug for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "Prefix({:b})", self)
    }
}

impl<T> Borrow<Prefix> for (Prefix, T) {
    fn borrow(&self) -> &Prefix {
        &self.0
    }
}

#[derive(Debug)]
pub struct FromStrError {
    pub invalid_char: char,
}

impl Display for FromStrError {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "'{}' not allowed - the string must represent a binary number.",
            self.invalid_char
        )
    }
}

impl FromStr for Prefix {
    type Err = FromStrError;

    fn from_str(bits: &str) -> Result<Self, Self::Err> {
        let mut name = [0; XOR_NAME_LEN];
        for (i, bit) in bits.chars().enumerate() {
            if bit == '1' {
                let byte = i / 8;
                name[byte] |= 1 << (7 - i);
            } else if bit != '0' {
                return Err(FromStrError { invalid_char: bit });
            }
        }
        Ok(Self::new(bits.len(), XorName(name)))
    }
}

/// Iterator that yields the ancestors of the given prefix starting at the root prefix.
/// Does not include the prefix itself.
pub struct Ancestors {
    target: Prefix,
    current_len: usize,
}

impl Iterator for Ancestors {
    type Item = Prefix;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_len < self.target.bit_count() {
            let output = self.target.ancestor(self.current_len as u8);
            self.current_len += 1;
            Some(output)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::SmallRng, seq::SliceRandom, SeedableRng};

    #[test]
    fn prefix() {
        assert_eq!(parse("101").pushed(true), parse("1011"));
        assert_eq!(parse("101").pushed(false), parse("1010"));
        assert_eq!(parse("1011").popped(), parse("101"));
        assert!(parse("101").is_compatible(&parse("1010")));
        assert!(parse("1010").is_compatible(&parse("101")));
        assert!(!parse("1010").is_compatible(&parse("1011")));
        assert!(parse("101").is_neighbour(&parse("1111")));
        assert!(!parse("1010").is_neighbour(&parse("1111")));
        assert!(parse("1010").is_neighbour(&parse("10111")));
        assert!(!parse("101").is_neighbour(&parse("10111")));
        assert!(parse("101").matches(&xor_name!(0b10101100)));
        assert!(!parse("1011").matches(&xor_name!(0b10101100)));

        assert_eq!(parse("0101").lower_bound(), xor_name!(0b01010000));
        assert_eq!(
            parse("0101").upper_bound(),
            xor_name!(
                0b01011111, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255
            )
        );

        // Check we handle passing an excessive `bit_count` to `new()`.
        assert_eq!(Prefix::new(256, xor_name!(0)).bit_count(), 256);
        assert_eq!(Prefix::new(257, xor_name!(0)).bit_count(), 256);
    }

    #[test]
    fn breadth_first_order() {
        let expected = [
            parse(""),
            parse("0"),
            parse("1"),
            parse("00"),
            parse("01"),
            parse("10"),
            parse("11"),
            parse("000"),
            parse("001"),
            parse("010"),
            parse("011"),
            parse("100"),
            parse("101"),
            parse("110"),
            parse("111"),
        ];

        let mut rng = SmallRng::from_entropy();

        for _ in 0..100 {
            let mut actual = expected;
            actual.shuffle(&mut rng);
            actual.sort_by(|lhs, rhs| lhs.cmp_breadth_first(rhs));

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn ancestors() {
        let mut ancestors = parse("").ancestors();
        assert_eq!(ancestors.next(), None);

        let mut ancestors = parse("0").ancestors();
        assert_eq!(ancestors.next(), Some(parse("")));
        assert_eq!(ancestors.next(), None);

        let mut ancestors = parse("01").ancestors();
        assert_eq!(ancestors.next(), Some(parse("")));
        assert_eq!(ancestors.next(), Some(parse("0")));
        assert_eq!(ancestors.next(), None);

        let mut ancestors = parse("011").ancestors();
        assert_eq!(ancestors.next(), Some(parse("")));
        assert_eq!(ancestors.next(), Some(parse("0")));
        assert_eq!(ancestors.next(), Some(parse("01")));
        assert_eq!(ancestors.next(), None);
    }

    #[test]
    fn format_binary() {
        assert_eq!(&format!(0, "{:b}", parse("")), "");
        assert_eq!(&format!(1, "{:b}", parse("0")), "0");
        assert_eq!(&format!(2, "{:b}", parse("00")), "00");
        assert_eq!(&format!(2, "{:b}", parse("01")), "01");
        assert_eq!(&format!(2, "{:b}", parse("10")), "10");
        assert_eq!(&format!(2, "{:b}", parse("11")), "11");
        assert_eq!(&format!(7, "{:b}", parse("1100101")), "1100101");
    }

    fn parse(input: &str) -> Prefix {
        Prefix::from_str(input).unwrap()
    }
}
