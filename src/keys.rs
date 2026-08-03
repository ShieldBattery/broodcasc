//! Key types used throughout CASC storage.
//!
//! A [`ContentKey`] (CKey) is the MD5 of a file's decoded contents; it's what
//! the root file maps names to. An [`EncodingKey`] (EKey) is the MD5 of the
//! encoded (BLTE) representation; it's what indices and archives are addressed
//! by. The encoding file maps CKeys to EKeys. Local `.idx` indices store only
//! the first 9 bytes of an EKey ([`TruncatedKey`]).

use core::fmt;

use crate::error::CascError;

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident, $len:literal, $what:literal) => {
        $(#[$doc])*
        #[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LENGTH: usize = $len;

            #[inline]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self, CascError> {
                bytes
                    .try_into()
                    .map($name)
                    .map_err(|_| CascError::malformed($what, "wrong key length"))
            }

            /// Parses a lowercase or uppercase hex string of exactly
            /// `2 * LENGTH` characters.
            pub fn from_hex(s: &str) -> Result<Self, CascError> {
                let s = s.as_bytes();
                if s.len() != $len * 2 {
                    return Err(CascError::malformed($what, "wrong hex length"));
                }
                let mut out = [0u8; $len];
                for (i, chunk) in s.chunks_exact(2).enumerate() {
                    let hi = hex_val(chunk[0]).ok_or(())
                        .map_err(|_| CascError::malformed($what, "invalid hex"))?;
                    let lo = hex_val(chunk[1]).ok_or(())
                        .map_err(|_| CascError::malformed($what, "invalid hex"))?;
                    out[i] = (hi << 4) | lo;
                }
                Ok($name(out))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                $name(bytes)
            }
        }
    };
}

key_type!(
    /// MD5 of a file's decoded contents ("CKey").
    ContentKey, 16, "content key"
);
key_type!(
    /// MD5 of a file's encoded (BLTE) representation ("EKey").
    EncodingKey, 16, "encoding key"
);
key_type!(
    /// The 9-byte EKey prefix stored in local `.idx` indices.
    TruncatedKey, 9, "truncated key"
);

impl EncodingKey {
    /// The truncated form of this key, as used by local indices.
    pub fn truncated(&self) -> TruncatedKey {
        let mut out = [0u8; 9];
        out.copy_from_slice(&self.0[..9]);
        TruncatedKey(out)
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_ok::assert_ok;

    #[test]
    fn hex_round_trip() {
        let key = assert_ok!(ContentKey::from_hex("b96213f265684e16db5a8552eba1be09"));
        assert_eq!(key.to_string(), "b96213f265684e16db5a8552eba1be09");
        assert_eq!(key.as_bytes()[0], 0xb9);
        assert_eq!(key.as_bytes()[15], 0x09);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(ContentKey::from_hex("b96213").is_err());
        assert!(ContentKey::from_hex("zz6213f265684e16db5a8552eba1be09").is_err());
    }

    #[test]
    fn truncation() {
        let key = assert_ok!(EncodingKey::from_hex("b135dde729b026904eeb4b7e76332750"));
        assert_eq!(key.truncated().to_string(), "b135dde729b026904e");
    }
}
