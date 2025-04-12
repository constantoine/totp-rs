//! Representation of a secret either a "raw" \[u8\] or "base 32" encoded String
//!
//! # Examples
//!
//! - Create a TOTP from a "raw" secret
//! ```
//! # #[cfg(not(feature = "otpauth"))] {
//! use totp_rs::{Secret, TOTP, Algorithm};
//!
//! let secret = [
//!     0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
//!     0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
//! ];
//! let secret_raw = Secret::Raw(secret.to_vec());
//! let totp_raw = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     secret_raw.to_bytes().unwrap(),
//! ).unwrap();
//!
//! println!("code from raw secret:\t{}", totp_raw.generate_current().unwrap());
//! # }
//! ```
//!
//! - Create a TOTP from a base32 encoded secret
//! ```
//! # #[cfg(not(feature = "otpauth"))] {
//! use totp_rs::{Secret, TOTP, Algorithm};
//!
//! let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
//! let totp_b32 = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     secret_b32.to_bytes().unwrap(),
//! ).unwrap();
//!
//! println!("code from base32:\t{}", totp_b32.generate_current().unwrap());
//! # }
//!
//! ```
//! - Create a TOTP from a Generated Secret
//! ```
//! # #[cfg(all(feature = "gen_secret", not(feature = "otpauth")))] {
//! use totp_rs::{Secret, TOTP, Algorithm};
//!
//! let secret_b32 = Secret::default();
//! let totp_b32 = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     secret_b32.to_bytes().unwrap(),
//! ).unwrap();
//!
//! println!("code from base32:\t{}", totp_b32.generate_current().unwrap());
//! # }
//! ```
//! - Create a TOTP from a Generated Secret 2
//! ```
//! # #[cfg(all(feature = "gen_secret", not(feature = "otpauth")))] {
//! use totp_rs::{Secret, TOTP, Algorithm};
//!
//! let secret_b32 = Secret::generate_secret();
//! let totp_b32 = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     secret_b32.to_bytes().unwrap(),
//! ).unwrap();
//!
//! println!("code from base32:\t{}", totp_b32.generate_current().unwrap());
//! # }
//! ```

use base32::{self, Alphabet};

use constant_time_eq::constant_time_eq;

/// Different ways secret parsing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretParseError {
    /// Invalid base32 input.
    ParseBase32,
}

impl std::error::Error for SecretParseError {}

impl std::fmt::Display for SecretParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretParseError::ParseBase32 => write!(f, "Could not decode base32 secret."),
        }
    }
}

impl std::error::Error for Secret {}

/// Shared secret between client and server to validate token against/generate token from.
#[derive(Debug, Clone, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub enum Secret {
    /// Non-encoded "raw" secret.
    Raw(Vec<u8>),
    /// Base32 encoded secret.
    Encoded(String),
}

impl PartialEq for Secret {
    /// Will check that to_bytes() returns the same.
    /// One secret can be Raw, and the other Encoded.
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.to_bytes().unwrap(), &other.to_bytes().unwrap())
    }
}

#[cfg(feature = "gen_secret")]
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Secret {
    fn default() -> Self {
        Secret::generate_secret()
    }
}

impl Secret {
    /// Get the inner String value as a Vec of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SecretParseError> {
        match self {
            Secret::Raw(s) => Ok(s.to_vec()),
            Secret::Encoded(s) => match base32::decode(Alphabet::Rfc4648 { padding: false }, s) {
                Some(bytes) => Ok(bytes),
                None => Err(SecretParseError::ParseBase32),
            },
        }
    }

    /// Try to transform a `Secret::Encoded` into a `Secret::Raw`
    pub fn to_raw(&self) -> Result<Self, SecretParseError> {
        match self {
            Secret::Raw(_) => Ok(self.clone()),
            Secret::Encoded(s) => match base32::decode(Alphabet::Rfc4648 { padding: false }, s) {
                Some(buf) => Ok(Secret::Raw(buf)),
                None => Err(SecretParseError::ParseBase32),
            },
        }
    }

    /// Try to transforms a `Secret::Raw` into a `Secret::Encoded`.
    pub fn to_encoded(&self) -> Self {
        match self {
            Secret::Raw(s) => {
                Secret::Encoded(base32::encode(Alphabet::Rfc4648 { padding: false }, s))
            }
            Secret::Encoded(_) => self.clone(),
        }
    }

    /// Generate a CSPRNG binary value of 160 bits,
    /// the recomended size from [rfc-4226](https://www.rfc-editor.org/rfc/rfc4226#section-4).
    ///
    /// > The length of the shared secret MUST be at least 128 bits.
    /// > This document RECOMMENDs a shared secret length of 160 bits.
    ///
    /// ⚠️ The generated secret is not guaranteed to be a valid UTF-8 sequence.
    #[cfg(feature = "gen_secret")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
    pub fn generate_secret() -> Secret {
        use rand::Rng;

        let mut rng = rand::rng();
        let mut secret: [u8; 20] = Default::default();
        rng.fill(&mut secret[..]);
        Secret::Raw(secret.to_vec())
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Raw(bytes) => {
                for b in bytes {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Secret::Encoded(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    const BASE32: &str = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    const BYTES: [u8; 23] = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];
    const BYTES_DISPLAY: &str = "706c61696e2d737472696e672d7365637265742d313233";

    #[test]
    fn secret_display() {
        let base32_str = String::from(BASE32);
        let secret_raw = Secret::Raw(BYTES.to_vec());
        let secret_base32 = Secret::Encoded(base32_str);
        println!("{}", secret_raw);
        assert_eq!(secret_raw.to_string(), BYTES_DISPLAY.to_string());
        assert_eq!(secret_base32.to_string(), BASE32.to_string());
    }

    #[test]
    fn secret_convert_base32_raw() {
        let base32_str = String::from(BASE32);
        let secret_raw = Secret::Raw(BYTES.to_vec());
        let secret_base32 = Secret::Encoded(base32_str);

        assert_eq!(&secret_raw.to_encoded(), &secret_base32);
        assert_eq!(&secret_raw.to_raw().unwrap(), &secret_raw);

        assert_eq!(&secret_base32.to_raw().unwrap(), &secret_raw);
        assert_eq!(&secret_base32.to_encoded(), &secret_base32);
    }

    #[test]
    fn secret_as_bytes() {
        let base32_str = String::from(BASE32);
        assert_eq!(
            Secret::Raw(BYTES.to_vec()).to_bytes().unwrap(),
            BYTES.to_vec()
        );
        assert_eq!(
            Secret::Encoded(base32_str).to_bytes().unwrap(),
            BYTES.to_vec()
        );
    }

    #[test]
    fn secret_from_string() {
        let raw: Secret = Secret::Raw("TestSecretSuperSecret".as_bytes().to_vec());
        let encoded: Secret = Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string());
        assert_eq!(raw.to_encoded(), encoded);
        assert_eq!(raw, encoded.to_raw().unwrap());
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_secret() {
        let sec = Secret::generate_secret();

        assert!(matches!(sec, Secret::Raw(_)));
        assert_eq!(sec.to_bytes().unwrap().len(), 20);
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_default() {
        let sec = Secret::default();

        assert!(matches!(sec, Secret::Raw(_)));
        assert_eq!(sec.to_bytes().unwrap().len(), 20);
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_empty() {
        let non_ascii = vec![240, 159, 146, 150];
        let sec = Secret::Encoded(std::str::from_utf8(&non_ascii).unwrap().to_owned());

        let to_r = sec.to_raw();

        assert!(to_r.is_err());

        let to_b = sec.to_bytes();

        assert!(to_b.is_err());
    }
}
