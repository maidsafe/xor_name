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
#![no_std]

use core::{cmp::Ordering, fmt, ops};
pub use prefix::Prefix;
use rand::{
    distributions::{Distribution, Standard},
    Rng, rngs::OsRng
};
use serde::{Deserialize, Serialize};
use rand_core::RngCore;
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

// No-std replacement for std::format! macro which returns `ArrayString` instead of `String`. The
// capacity of the returned `ArrayString` needs to explicitly given as the first argument.
#[cfg(test)]
macro_rules! format {
    ($capacity:expr, $($arg:tt)*) => {{
        let mut output = arrayvec::ArrayString::<[_; $capacity]>::new();
        core::fmt::write(&mut output, core::format_args!($($arg)*)).expect("insufficient ArrayString capacity");
        output
    }}
}

mod prefix;

/// Constant byte length of `XorName`.
pub const XOR_NAME_LEN: usize = 32;

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
    /// Generate a random Xorname
    pub fn random() -> XorName {
        let mut xor = [0u8; XOR_NAME_LEN];
        OsRng.fill_bytes(&mut xor);

        Self(xor)
    }

    /// Returns `true` if the `i`-th bit is `1`.
    pub fn bit(&self, i: u8) -> bool {
        let index = i / 8;
        let pow_i = 1 << (7 - (i % 8));
        self[index as usize] & pow_i != 0
    }

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    pub fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
        for i in 0..XOR_NAME_LEN {
            if lhs[i] != rhs[i] {
                return Ord::cmp(&(lhs[i] ^ self[i]), &(rhs[i] ^ self[i]));
            }
        }
        Ordering::Equal
    }

    /// Returns a copy of `self`, with the `i`-th bit set to `bit`.
    ///
    /// If `i` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    fn with_bit(mut self, i: u8, bit: bool) -> Self {
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
    fn with_flipped_bit(mut self, i: u8) -> Self {
        if i as usize >= XOR_NAME_LEN * 8 {
            return self;
        }
        self.0[i as usize / 8] ^= 1 << (7 - i % 8);
        self
    }

    /// Returns a copy of self with first `n` bits preserved, and remaining bits
    /// set to 0 (val == false) or 1 (val == true).
    fn set_remaining(mut self, n: u8, val: bool) -> Self {
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

    /// Returns the length of the common prefix with the `other` name; e. g.
    /// the when `other = 11110000` and `self = 11111111` this is 4.
    fn common_prefix(&self, other: &Self) -> usize {
        for byte_index in 0..XOR_NAME_LEN {
            if self[byte_index] != other[byte_index] {
                return (byte_index * 8)
                    + (self[byte_index] ^ other[byte_index]).leading_zeros() as usize;
            }
        }
        8 * XOR_NAME_LEN
    }
}

impl fmt::Debug for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self)
    }
}

impl fmt::Display for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:02x}{:02x}{:02x}..", self[0], self[1], self[2])
    }
}

impl fmt::Binary for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        if let Some(width) = formatter.width() {
            let whole_bytes = width / 8;
            let remaining_bits = width % 8;

            for byte in &self[..whole_bytes] {
                write!(formatter, "{:08b}", byte)?
            }

            for bit in 0..remaining_bits {
                write!(formatter, "{}", (self[whole_bytes] >> (7 - bit)) & 1)?;
            }

            if formatter.alternate() && whole_bytes < XOR_NAME_LEN - 1 {
                write!(formatter, "..")?;
            }
        } else {
            for byte in &self[..] {
                write!(formatter, "{:08b}", byte)?
            }
        }
        Ok(())
    }
}

impl fmt::LowerHex for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let bytes = formatter.width().unwrap_or(2 * XOR_NAME_LEN) / 2;

        for byte in &self[..bytes] {
            write!(formatter, "{:02x}", byte)?;
        }

        if formatter.alternate() && bytes < XOR_NAME_LEN {
            write!(formatter, "..")?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for XorName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let bytes = formatter.width().unwrap_or(2 * XOR_NAME_LEN) / 2;

        for byte in &self[..bytes] {
            write!(formatter, "{:02X}", byte)?;
        }

        if formatter.alternate() && bytes < XOR_NAME_LEN {
            write!(formatter, "..")?;
        }

        Ok(())
    }
}

impl Distribution<XorName> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> XorName {
        let mut name = XorName::default();
        rng.fill(&mut name.0[..]);
        name
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

impl AsRef<XorName> for XorName {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<[u8]> for XorName {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl ops::Deref for XorName {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{deserialize, serialize};
    use rand::{rngs::SmallRng, SeedableRng};

    #[test]
    fn create_random_xorname() {
        let xorname: XorName = XorName::random();
        let xorname2: XorName = XorName::random();

        assert_ne!(xorname, xorname2);
    }

    #[test]
    fn serialisation_xor_name() {
        let obj_before: XorName = XorName::random();
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
        let mut rng = SmallRng::from_entropy();
        let type1: XorName = rng.gen();
        let type1_clone = type1;
        let type2: XorName = rng.gen();
        assert_eq!(type1, type1_clone);
        assert!(!(type1 != type1_clone));
        assert_ne!(type1, type2);
    }

    #[test]
    fn format_debug() {
        assert_eq!(
            &format!(8, "{:?}", xor_name!(0x01, 0x23, 0x45, 0x67)),
            "012345.."
        );
        assert_eq!(
            &format!(8, "{:?}", xor_name!(0x89, 0xab, 0xcd, 0xdf)),
            "89abcd.."
        );
    }

    #[test]
    fn format_hex() {
        assert_eq!(
            &format!(64, "{:x}", xor_name!(0x01, 0x23, 0xab)),
            "0123ab0000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(&format!(2, "{:2x}", xor_name!(0x01, 0x23, 0xab)), "01");
        assert_eq!(&format!(4, "{:4x}", xor_name!(0x01, 0x23, 0xab)), "0123");
        assert_eq!(&format!(6, "{:6x}", xor_name!(0x01, 0x23, 0xab)), "0123ab");
        assert_eq!(
            &format!(8, "{:8x}", xor_name!(0x01, 0x23, 0xab)),
            "0123ab00"
        );
        assert_eq!(
            &format!(10, "{:10x}", xor_name!(0x01, 0x23, 0xab)),
            "0123ab0000"
        );
        assert_eq!(
            &format!(8, "{:8X}", xor_name!(0x01, 0x23, 0xab)),
            "0123AB00"
        );

        assert_eq!(
            &format!(8, "{:#6x}", xor_name!(0x01, 0x23, 0xab)),
            "0123ab.."
        );

        // odd widths are truncated to nearest even
        assert_eq!(&format!(2, "{:3x}", xor_name!(0x01, 0x23, 0xab)), "01");
        assert_eq!(&format!(4, "{:5x}", xor_name!(0x01, 0x23, 0xab)), "0123");
    }

    #[test]
    fn format_binary() {
        assert_eq!(
            &format!(256, "{:b}", xor_name!(0b00001111, 0b01010101)),
            "00001111010101010000000000000000000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(&format!(1, "{:1b}", xor_name!(0b00001111, 0b01010101)), "0");
        assert_eq!(
            &format!(2, "{:2b}", xor_name!(0b00001111, 0b01010101)),
            "00"
        );
        assert_eq!(
            &format!(3, "{:3b}", xor_name!(0b00001111, 0b01010101)),
            "000"
        );
        assert_eq!(
            &format!(4, "{:4b}", xor_name!(0b00001111, 0b01010101)),
            "0000"
        );
        assert_eq!(
            &format!(5, "{:5b}", xor_name!(0b00001111, 0b01010101)),
            "00001"
        );
        assert_eq!(
            &format!(6, "{:6b}", xor_name!(0b00001111, 0b01010101)),
            "000011"
        );
        assert_eq!(
            &format!(7, "{:7b}", xor_name!(0b00001111, 0b01010101)),
            "0000111"
        );
        assert_eq!(
            &format!(8, "{:8b}", xor_name!(0b00001111, 0b01010101)),
            "00001111"
        );
        assert_eq!(
            &format!(9, "{:9b}", xor_name!(0b00001111, 0b01010101)),
            "000011110"
        );
        assert_eq!(
            &format!(10, "{:10b}", xor_name!(0b00001111, 0b01010101)),
            "0000111101"
        );
        assert_eq!(
            &format!(16, "{:16b}", xor_name!(0b00001111, 0b01010101)),
            "0000111101010101"
        );
        assert_eq!(
            &format!(10, "{:#8b}", xor_name!(0b00001111, 0b01010101)),
            "00001111.."
        );
    }

    #[test]
    fn with_flipped_bit() {
        let mut rng = SmallRng::from_entropy();
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
        let mut rng = SmallRng::from_entropy();

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
