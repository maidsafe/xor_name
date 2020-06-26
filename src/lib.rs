// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! # xor-name
//!
//! TODO requires further documentation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    html_root_url = "http://maidsafe.github.io/xor_name"
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature = "clippy", allow(use_debug))]
#![allow(unused_extern_crates)]

use hex::{FromHex, FromHexError, ToHex};
use log::error;
use num_bigint::BigUint;
pub use prefix::Prefix;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::ops;

/// Creates XorName with the given leading bytes and the rest filled with zeroes.
#[macro_export]
macro_rules! xor_name {
    ($($byte:expr),* $(,)?) => {{
        let mut name = $crate::XorName::default();
        let mut index = 0;

        #[allow(unused_assignments)]
        {
            $(
                name.0[index] = $byte;
                index += 1;
            )*
        }

        name
    }}
}

mod prefix;

/// Constant byte length of `XorName`.
pub const XOR_NAME_LEN: usize = 32;

/// Errors that can occur when decoding a `XorName` from a string.
#[derive(Debug)]
pub enum XorNameFromHexError {
    /// The given invalid hex character occurred at the given position.
    InvalidCharacter(char, usize),
    /// The hex string did not encode `XOR_NAME_LEN` bytes.
    WrongLength,
}

/// A 256-bit number, viewed as a point in XOR space.
///
/// This wraps an array of 32 bytes, i. e. a number between 0 and 2<sup>256</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[derive(Eq, Copy, Clone, Default, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct XorName(pub [u8; XOR_NAME_LEN]);

impl XorName {
    /// Returns `true` if the `i`-th bit is `1`.
    pub fn bit(&self, i: u8) -> bool {
        let index = i / 8;
        let pow_i = 1 << (7 - (i % 8));
        self.0[index as usize] & pow_i != 0
    }

    /// Returns a copy of `self`, with the `i`-th bit set to `bit`.
    ///
    /// If `i` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    pub fn with_bit(mut self, i: u8, bit: bool) -> Self {
        if i as usize >= XOR_NAME_LEN * 8 {
            return self;
        }
        let pow_i = 1 << (7 - i % 8);
        if bit {
            self.0[i as usize / 8] |= pow_i;
        } else {
            self.0[i as usize / 8] &= !pow_i;
        }
        self
    }

    /// Returns a copy of `self`, with the `i`-th bit flipped.
    ///
    /// If `i` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    pub fn with_flipped_bit(mut self, i: u8) -> Self {
        if i as usize >= XOR_NAME_LEN * 8 {
            return self;
        }
        self.0[i as usize / 8] ^= 1 << (7 - i % 8);
        self
    }

    /// Returns a copy of self with first `n` bits preserved, and remaining bits
    /// set to 0 (val == false) or 1 (val == true).
    pub fn set_remaining(mut self, n: u8, val: bool) -> Self {
        for (i, x) in self.0.iter_mut().enumerate() {
            let i = i as u8;

            if n <= i * 8 {
                *x = if val { !0 } else { 0 };
            } else if n < (i + 1) * 8 {
                let mask = !0 >> (n - i * 8);
                if val {
                    *x |= mask
                } else {
                    *x &= !mask
                }
            }
            // else n >= (i+1) * bits: nothing to do
        }
        self
    }

    /// Hex-encode the `XorName` as a `String`.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns `true` if the `i`-th bit of other has a different value to the `i`-th bit of `self`.
    pub fn differs_in_bit(&self, other: &Self, i: u8) -> bool {
        let index = i / 8;
        let pow_i = 1 << (7 - (i % 8));
        (self.0[index as usize] ^ other.0[index as usize]) & pow_i != 0
    }

    /// Returns the number of bits in which `self` differs from `other`.
    pub fn count_differing_bits(&self, other: &Self) -> u32 {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0, |acc, (a, b)| acc + (a ^ b).count_ones())
    }

    /// Hex-decode a `XorName` from a `&str`.
    pub fn from_hex(s: &str) -> Result<Self, XorNameFromHexError> {
        let data: Vec<u8> = match FromHex::from_hex(&s) {
            Ok(v) => v,
            Err(FromHexError::InvalidHexCharacter { c, index }) => {
                return Err(XorNameFromHexError::InvalidCharacter(c, index));
            }
            Err(FromHexError::InvalidHexLength) => return Err(XorNameFromHexError::WrongLength),
        };
        if data.len() != XOR_NAME_LEN {
            return Err(XorNameFromHexError::WrongLength);
        }

        let mut inner = [0u8; XOR_NAME_LEN];
        inner.copy_from_slice(&data);

        Ok(Self(inner))
    }

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    pub fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
        for i in 0..XOR_NAME_LEN {
            if lhs.0[i] != rhs.0[i] {
                return Ord::cmp(&(lhs.0[i] ^ self.0[i]), &(rhs.0[i] ^ self.0[i]));
            }
        }
        Ordering::Equal
    }

    /// Returns true if `lhs` is closer to `self` than `rhs`.
    ///
    /// Equivalently, this returns `true` if in the most significant bit where `lhs` and `rhs`
    /// disagree, `lhs` agrees with `self`.
    pub fn closer(&self, lhs: &Self, rhs: &Self) -> bool {
        self.cmp_distance(lhs, rhs) == Ordering::Less
    }

    /// Returns true if `lhs` is closer to `self` than `rhs`, or `lhs == rhs`.
    pub fn closer_or_equal(&self, lhs: &Self, rhs: &Self) -> bool {
        self.cmp_distance(lhs, rhs) != Ordering::Greater
    }

    /// Returns the length of the common prefix with the `other` name; e. g.
    /// the when `other = 11110000` and `self = 11111111` this is 4.
    pub fn common_prefix(&self, other: &Self) -> usize {
        for byte_index in 0..XOR_NAME_LEN {
            if self.0[byte_index] != other.0[byte_index] {
                return (byte_index * 8)
                    + (self.0[byte_index] ^ other.0[byte_index]).leading_zeros() as usize;
            }
        }
        8 * XOR_NAME_LEN
    }

    /// Returns a binary format string, with leading zero bits included.
    pub fn binary(&self) -> String {
        let mut s = String::with_capacity(8 * XOR_NAME_LEN);
        for byte in &self.0 {
            s.push_str(&format!("{1:00$b}", 8, byte))
        }
        s
    }

    /// Returns a binary debug format string of `????????...????????`
    pub fn debug_binary(&self) -> String {
        debug_format(self.binary())
    }

    /// Private function exposed in fmt Debug {:?} and Display {} traits.
    fn get_debug_id(&self) -> String {
        format!("{:02x}{:02x}{:02x}..", self.0[0], self.0[1], self.0[2])
    }

    /// Used to construct an XorName from a `BigUint`. `value` should not represent a number greater
    /// than or equal to `2^XOR_NAME_BITS`. If it does, the excessive most significant bits are
    /// ignored.
    fn from_big_uint(value: BigUint) -> Self {
        let little_endian_value = value.to_bytes_le();
        if little_endian_value.len() > XOR_NAME_LEN {
            error!("This BigUint value exceeds the maximum capable of being held as an XorName.");
        }
        // Convert the little-endian vector to a 32-byte big-endian array.
        let mut xor_name = Self::default();
        for (xor_name_elt, little_endian_elt) in
            xor_name.0.iter_mut().rev().zip(little_endian_value.iter())
        {
            *xor_name_elt = *little_endian_elt;
        }
        xor_name
    }
}

impl fmt::Debug for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.get_debug_id())
    }
}

impl fmt::Display for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.get_debug_id())
    }
}

impl fmt::Binary for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.debug_binary())
    }
}

impl Distribution<XorName> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> XorName {
        let mut ret = [0u8; XOR_NAME_LEN];
        for r in ret[..].iter_mut() {
            *r = rng.gen::<u8>();
        }
        XorName(ret)
    }
}

impl ops::Index<ops::Range<usize>> for XorName {
    type Output = [u8];

    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        let Self(b) = self;
        b.index(index)
    }
}
impl ops::Index<ops::RangeTo<usize>> for XorName {
    type Output = [u8];

    fn index(&self, index: ops::RangeTo<usize>) -> &[u8] {
        let Self(b) = self;
        b.index(index)
    }
}

impl ops::Index<ops::RangeFrom<usize>> for XorName {
    type Output = [u8];

    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        let Self(b) = self;
        b.index(index)
    }
}

impl ops::Index<ops::RangeFull> for XorName {
    type Output = [u8];

    fn index(&self, index: ops::RangeFull) -> &[u8] {
        let Self(b) = self;
        b.index(index)
    }
}

impl ops::Not for XorName {
    type Output = Self;

    fn not(mut self) -> Self {
        for byte in &mut self.0 {
            *byte = !*byte;
        }
        self
    }
}

impl ops::Sub for XorName {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        (&self).sub(&rhs)
    }
}

impl<'a> ops::Sub for &'a XorName {
    type Output = XorName;

    fn sub(self, rhs: &XorName) -> Self::Output {
        XorName::from_big_uint(BigUint::from_bytes_be(&self.0) - BigUint::from_bytes_be(&rhs.0))
    }
}

impl ops::Div<u32> for XorName {
    type Output = Self;

    fn div(self, rhs: u32) -> Self::Output {
        (&self).div(&rhs)
    }
}

impl<'a> ops::Div<&'a u32> for &'a XorName {
    type Output = XorName;

    fn div(self, rhs: &u32) -> Self::Output {
        XorName::from_big_uint(BigUint::from_bytes_be(&self.0) / BigUint::new(vec![*rhs]))
    }
}

impl AsRef<XorName> for XorName {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Converts a string into debug format of `????????...????????` when the string is longer than 20.
fn debug_format(input: String) -> String {
    if input.len() <= 20 {
        return input;
    }
    input
        .chars()
        .take(8)
        .chain("...".chars())
        .chain(input.chars().skip(input.len() - 8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{deserialize, serialize};
    use std::cmp::Ordering;

    #[test]
    fn serialisation_xor_name() {
        let mut rng = rand::thread_rng();
        let obj_before: XorName = rng.gen();
        let data = serialize(&obj_before).unwrap();
        assert_eq!(data.len(), XOR_NAME_LEN);
        let obj_after: XorName = deserialize(&data).unwrap();
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn xor_name_ord() {
        let type1: XorName = XorName([1u8; XOR_NAME_LEN]);
        let type2: XorName = XorName([2u8; XOR_NAME_LEN]);
        assert_eq!(Ord::cmp(&type1, &type1), Ordering::Equal);
        assert_eq!(Ord::cmp(&type1, &type2), Ordering::Less);
        assert_eq!(Ord::cmp(&type2, &type1), Ordering::Greater);
        assert!(type1 < type2);
        assert!(type1 <= type2);
        assert!(type1 <= type1);
        assert!(type2 > type1);
        assert!(type2 >= type1);
        assert!(type1 >= type1);
        assert!(!(type2 < type1));
        assert!(!(type2 <= type1));
        assert!(!(type1 > type2));
        assert!(!(type1 >= type2));
    }

    #[test]
    fn xor_name_equal_assertion() {
        let mut rng = rand::thread_rng();
        let type1: XorName = rng.gen();
        let type1_clone = type1;
        let type2: XorName = rng.gen();
        assert_eq!(type1, type1_clone);
        assert!(!(type1 != type1_clone));
        assert_ne!(type1, type2);
    }

    #[test]
    fn closeness() {
        let mut rng = rand::thread_rng();
        let obj0: XorName = rng.gen();
        let obj0_clone = obj0;
        let obj1: XorName = rng.gen();
        assert!(obj0.closer(&obj0_clone, &obj1));
        assert!(!obj0.closer(&obj1, &obj0_clone));
    }

    #[test]
    fn format_nametype() {
        // test for
        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            let my_name: XorName = rng.gen();
            let debug_id = my_name.get_debug_id();
            let full_id = my_name.to_hex();
            assert_eq!(debug_id.len(), 8);
            assert_eq!(full_id.len(), 2 * XOR_NAME_LEN);
            assert_eq!(&debug_id[0..6].to_owned(), &full_id[0..6]);
        }
    }

    #[test]
    fn format_fixed_low_char_nametype() {
        // test for fixed low char values in XorName
        let low_char_id = [1u8; XOR_NAME_LEN];
        let my_low_char_name = XorName(low_char_id);
        let debug_id = my_low_char_name.get_debug_id();
        let full_id = my_low_char_name.to_hex();
        assert_eq!(debug_id.len(), 8);
        assert_eq!(full_id.len(), 2 * XOR_NAME_LEN);
        assert_eq!(&debug_id[0..6], &full_id[0..6].to_owned());
    }

    #[test]
    fn with_flipped_bit() {
        let mut rng = rand::thread_rng();
        let name: XorName = rng.gen();
        for i in 0..18 {
            assert_eq!(i, name.common_prefix(&name.with_flipped_bit(i as u8)));
        }
        for i in 0..10 {
            assert_eq!(
                19 * i,
                name.common_prefix(&name.with_flipped_bit(19 * i as u8))
            );
        }
    }

    #[test]
    fn count_differing_bits() {
        let mut rng = rand::thread_rng();
        let name: XorName = rng.gen();
        assert_eq!(0, name.count_differing_bits(&name));
        let one_bit = name.with_flipped_bit(5);
        assert_eq!(1, name.count_differing_bits(&one_bit));
        let two_bits = one_bit.with_flipped_bit(100);
        assert_eq!(2, name.count_differing_bits(&two_bits));
    }

    #[test]
    fn subtraction() {
        let mut rng = rand::thread_rng();
        for _ in 0..100_000 {
            let x = rng.gen();
            let y = rng.gen();
            let (larger, smaller) = if x > y { (x, y) } else { (y, x) };
            assert_eq!(
                &from_u64(larger - smaller)[..],
                &(from_u64(larger) - from_u64(smaller))[..]
            );
            assert_eq!(XorName::default(), from_u64(x) - from_u64(x));
        }
    }

    #[test]
    #[should_panic]
    fn subtraction_underflow() {
        let _ = from_u64(1_000_001) - from_u64(1_000_002);
    }

    #[test]
    fn division() {
        let mut rng = rand::thread_rng();
        for _ in 0..100_000 {
            let x = rng.gen();
            let y = rng.gen::<u32>().saturating_add(1);
            assert_eq!(from_u64(x / u64::from(y)), from_u64(x) / y);
            assert_eq!(from_u64(1), from_u64(u64::from(y)) / y);
        }
    }

    #[test]
    fn common_prefix() {
        assert_eq!(
            0,
            xor_name!(0b00000000).common_prefix(&xor_name!(0b10000000))
        );
        assert_eq!(
            3,
            xor_name!(0b11100000).common_prefix(&xor_name!(0b11111111))
        );
        assert_eq!(
            5,
            xor_name!(0b10101010).common_prefix(&xor_name!(0b10101111))
        );
        assert_eq!(
            0,
            xor_name!(0, 0, 0, 0).common_prefix(&xor_name!(128, 0, 0, 0))
        );
        assert_eq!(
            11,
            xor_name!(0, 10, 0, 0).common_prefix(&xor_name!(0, 16, 0, 0))
        );
        assert_eq!(
            31,
            xor_name!(1, 2, 3, 4).common_prefix(&xor_name!(1, 2, 3, 5))
        );
        assert_eq!(
            256,
            xor_name!(1, 2, 3, 4).common_prefix(&xor_name!(1, 2, 3, 4))
        );
    }

    #[test]
    fn cmp_distance() {
        assert_eq!(
            xor_name!(42).cmp_distance(&xor_name!(13), &xor_name!(13)),
            Ordering::Equal,
        );
        assert_eq!(
            xor_name!(42).cmp_distance(&xor_name!(44), &xor_name!(45)),
            Ordering::Less,
        );
        assert_eq!(
            xor_name!(42).cmp_distance(&xor_name!(45), &xor_name!(44)),
            Ordering::Greater,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(2, 3, 4, 5), &xor_name!(2, 3, 4, 5)),
            Ordering::Equal,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(2, 2, 4, 5), &xor_name!(2, 3, 6, 5)),
            Ordering::Less,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(2, 3, 6, 5), &xor_name!(2, 2, 4, 5)),
            Ordering::Greater,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(1, 2, 3, 8), &xor_name!(1, 2, 8, 4)),
            Ordering::Less,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(1, 2, 8, 4), &xor_name!(1, 2, 3, 8)),
            Ordering::Greater,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(1, 2, 7, 4), &xor_name!(1, 2, 6, 4)),
            Ordering::Less,
        );
        assert_eq!(
            xor_name!(1, 2, 3, 4).cmp_distance(&xor_name!(1, 2, 6, 4), &xor_name!(1, 2, 7, 4)),
            Ordering::Greater,
        );
    }

    #[test]
    fn bit() {
        assert_eq!(false, xor_name!(0b00101000).bit(0));
        assert_eq!(true, xor_name!(0b00101000).bit(2));
        assert_eq!(false, xor_name!(0b00101000).bit(3));
        assert_eq!(true, xor_name!(2, 128, 1, 0).bit(6));
        assert_eq!(true, xor_name!(2, 128, 1, 0).bit(8));
        assert_eq!(true, xor_name!(2, 128, 1, 0).bit(23));
        assert_eq!(false, xor_name!(2, 128, 1, 0).bit(5));
        assert_eq!(false, xor_name!(2, 128, 1, 0).bit(7));
        assert_eq!(false, xor_name!(2, 128, 1, 0).bit(9));
        assert_eq!(false, xor_name!(2, 128, 1, 0).bit(22));
        assert_eq!(false, xor_name!(2, 128, 1, 0).bit(24));
    }

    #[test]
    fn differs_in_bit() {
        assert!(xor_name!(0b00101010).differs_in_bit(&xor_name!(0b00100010), 4));
        assert!(xor_name!(0b00101010).differs_in_bit(&xor_name!(0b00000010), 4));
        assert!(!xor_name!(0b00101010).differs_in_bit(&xor_name!(0b00001010), 4));
        assert!(xor_name!(0, 0, 0, 0).differs_in_bit(&xor_name!(0, 1, 0, 10), 15));
        assert!(xor_name!(0, 7, 0, 0).differs_in_bit(&xor_name!(0, 0, 0, 0), 14));
        assert!(!xor_name!(0, 7, 0, 0).differs_in_bit(&xor_name!(0, 0, 0, 0), 26));
    }

    #[test]
    fn set_remaining() {
        assert_eq!(
            xor_name!(0b10011011).set_remaining(5, false),
            xor_name!(0b10011000)
        );
        assert_eq!(
            xor_name!(0b11111111).set_remaining(2, false),
            xor_name!(0b11000000)
        );
        assert_eq!(
            xor_name!(0b00000000).set_remaining(4, true),
            xor_name!(
                0b00001111, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255
            )
        );
        assert_eq!(
            xor_name!(13, 112, 9, 1).set_remaining(0, false),
            xor_name!(0, 0, 0, 0)
        );
        assert_eq!(
            xor_name!(13, 112, 9, 1).set_remaining(100, false),
            xor_name!(13, 112, 9, 1)
        );
        assert_eq!(
            xor_name!(13, 112, 9, 1).set_remaining(10, false),
            xor_name!(13, 64, 0, 0)
        );
        assert_eq!(
            xor_name!(13, 112, 9, 1).set_remaining(10, true),
            xor_name!(
                13, 127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
            )
        );
    }

    #[test]
    fn xor_name_macro() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let byte = rng.gen();
            assert_eq!(&xor_name!(byte)[..1], &[byte]);
        }

        for _ in 0..100 {
            let byte0 = rng.gen();
            let byte1 = rng.gen();
            assert_eq!(&xor_name!(byte0, byte1)[..2], &[byte0, byte1]);
        }

        for _ in 0..100 {
            let byte0 = rng.gen();
            let byte1 = rng.gen();
            let byte2 = rng.gen();
            assert_eq!(&xor_name!(byte0, byte1, byte2)[..3], &[byte0, byte1, byte2]);
        }
    }

    #[test]
    fn conversion_from_u64() {
        assert_eq!(
            &from_u64(0x0123456789abcdef)[XOR_NAME_LEN - 8..],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    // Create a `XorName` with the 8 trailing bytes equal to `x` (in big endian order) and the rest
    // filled with zeroes.
    fn from_u64(x: u64) -> XorName {
        let mut name = XorName::default();
        name.0[XOR_NAME_LEN - 8..].copy_from_slice(&x.to_be_bytes());
        name
    }
}
