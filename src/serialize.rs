use crate::{Prefix, XorName};
use serde::{
    de::{self, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

impl Serialize for XorName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Return string with hexadecimal representation
        if serializer.is_human_readable() {
            return serializer.serialize_str(&hex::encode(self.0));
        }

        // Default serialization.
        serializer.serialize_newtype_struct("XorName", &self.0)
    }
}

impl<'de> Deserialize<'de> for XorName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct XorNameHexStrVisitor;
            impl<'de> Visitor<'de> for XorNameHexStrVisitor {
                type Value = XorName;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "32 byte hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let buffer = <[u8; 32] as hex::FromHex>::from_hex(s)
                        .map_err(|e| E::custom(std::format!("hex decoding ({})", e)))?;
                    Ok(XorName(buffer))
                }
            }
            return deserializer.deserialize_str(XorNameHexStrVisitor);
        }

        #[derive(Deserialize)]
        #[serde(rename = "XorName")]
        struct XorNameDerived([u8; 32]);
        let x = <XorNameDerived as Deserialize>::deserialize(deserializer)?;
        Ok(XorName(x.0))
    }
}

impl Serialize for Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let hex_str = hex::encode(&self.name);
            let bit_count = self.bit_count;
            let s = std::format!("{hex_str}/{bit_count}");

            return serializer.serialize_str(&s);
        }

        let mut s = serializer.serialize_struct("Prefix", 2)?;
        s.serialize_field("bit_count", &self.bit_count)?;
        s.serialize_field("name", &self.name)?;
        s.end()
    }
}
impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct PrefixVisitor;
            impl<'de> Visitor<'de> for PrefixVisitor {
                type Value = Prefix;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        formatter,
                        "prefix in string format (\"<xor hex string>/<prefix>\")"
                    )
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let mut split = s.split('/');

                    let hex_str = split
                        .next()
                        .ok_or_else(|| de::Error::custom("`str::split` logic error"))?;
                    let bit_count = split
                        .next()
                        .ok_or_else(|| de::Error::custom("no `/` symbol encountered"))?;

                    let k: [u8; 32] = hex::FromHex::from_hex(hex_str)
                        .map_err(|_| de::Error::custom("invalid 32 byte hex string"))?;
                    let bit_count = bit_count
                        .parse::<usize>()
                        .map_err(|_e| de::Error::custom("bit_count is not a valid `usize`"))?;

                    Ok(Prefix::new(bit_count, XorName(k)))
                }
            }
            return deserializer.deserialize_str(PrefixVisitor);
        }

        #[derive(Deserialize)]
        #[serde(rename = "Prefix")]
        struct PrefixDerived {
            bit_count: u16,
            name: XorName,
        }
        let p = <PrefixDerived as Deserialize>::deserialize(deserializer)?;
        Ok(Prefix {
            bit_count: p.bit_count,
            name: p.name,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_test::*;

    /// `XorName` with derived `Serialize` impl. Used to compare against.
    #[derive(PartialEq, Debug, serde::Serialize, Deserialize)]
    struct XorNameDerived([u8; 32]);

    /// `Prefix` with derived `Serialize` impl. Used to compare against.
    #[derive(PartialEq, Debug, serde::Serialize, Deserialize)]
    struct PrefixDerived {
        bit_count: u16,
        name: XorNameDerived,
    }

    #[test]
    fn xorname_ser_de() {
        let xor = XorName([0xAA; 32]);
        let xor_derived = XorNameDerived([0xAA; 32]);

        let xor_hex_str = static_str("aa".repeat(32));
        assert_tokens(&xor.readable(), &[Token::Str(xor_hex_str)]);

        assert_tokens(&xor.compact(), &xor_tokens("XorName"));
        // Verify our `Serialize` impl is same as when it would be derived
        assert_tokens(&xor_derived.compact(), &xor_tokens("XorNameDerived"));
    }

    #[test]
    fn prefix_ser_de() {
        let prefix = Prefix {
            bit_count: 14,
            name: XorName([0xAA; 32]),
        };
        let prefix_derived = PrefixDerived {
            bit_count: 14,
            name: XorNameDerived([0xAA; 32]),
        };

        let xor_hex_str = static_str("aa".repeat(32) + "/14");
        assert_tokens(&prefix.readable(), &[Token::Str(xor_hex_str)]);

        assert_tokens(&prefix.compact(), &prefix_tokens("Prefix", "XorName"));
        // Verify our `Serialize` impl is same as when it would be derived
        assert_tokens(
            &prefix_derived.compact(),
            &prefix_tokens("PrefixDerived", "XorNameDerived"),
        );
    }

    // Little helper to leak a &str to obtain a static str (`Token::Str` requires &'static str)
    fn static_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    // Compact/derived representation of `XorName`
    fn xor_tokens(name: &'static str) -> Vec<Token> {
        let mut a = vec![];
        a.extend_from_slice(&[Token::NewtypeStruct { name }, Token::Tuple { len: 32 }]);
        a.extend_from_slice(&[Token::U8(0xAA); 32]); // Repeat a U8 Token 32 times
        a.extend_from_slice(&[Token::TupleEnd]);
        a
    }

    // Compact/derived representation of `Prefix`
    fn prefix_tokens(name: &'static str, name2: &'static str) -> Vec<Token> {
        let mut v = vec![
            Token::Struct { name, len: 2 },
            Token::Str("bit_count"),
            Token::U16(14),
            Token::Str("name"),
        ];
        v.extend_from_slice(&xor_tokens(name2));
        v.extend_from_slice(&[Token::StructEnd]);
        v
    }
}
