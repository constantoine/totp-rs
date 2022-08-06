use std::string::FromUtf8Error;

use base32::{self, Alphabet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretParseError {
    ParseBase32,
    Utf8Error(FromUtf8Error),
}

/// Representation of a secret either in "plain text" or "base 32" encoded
///
/// # Examples
///
/// - Create a TOTP from a "plain text" secret
/// ```
/// use totp_rs::{Secret, TOTP, Algorithm};
///
/// let secret = Secret::Plain(String::from("my-secret"));
/// let totp_plain = TOTP::new(
///     Algorithm::SHA1,
///     6,
///     1,
///     30,
///     secret.as_bytes().unwrap(),
///     None,
///     "account".to_string(),
/// ).unwrap();
///
/// println!("code from plain text:\t{}", totp_plain.generate_current().unwrap());
/// ```
///
/// - Create a TOTP from a base32 encoded secret
/// ```
/// use totp_rs::{Secret, TOTP, Algorithm};
///
/// let secret = Secret::Base32(String::from("NV4S243FMNZGK5A"));
/// let totp_base32 = TOTP::new(
///     Algorithm::SHA1,
///     6,
///     1,
///     30,
///     secret.as_bytes().unwrap(),
///     None,
///     "account".to_string(),
/// ).unwrap();
///
/// println!("code from base32:\t{}", totp_base32.generate_current().unwrap());
///
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    /// represent a non-encoded "plain text" secret
    Plain(String),
    /// represent a base32 encoded secret
    Base32(String),
}

impl Secret {
    /// Get the inner String value of the enum variant
    pub fn inner(&self) -> &String {
        match self {
            Secret::Plain(s) => s,
            Secret::Base32(s) => s,
        }
    }

    /// Get the inner String value as a Vec of bytes
    pub fn as_bytes(&self) -> Result<Vec<u8>, SecretParseError> {
        match self {
            Secret::Plain(s) => Ok(s.as_bytes().to_vec()),
            Secret::Base32(s) => match base32::decode(Alphabet::RFC4648 { padding: false }, s) {
                Some(bytes) => Ok(bytes),
                None => Err(SecretParseError::ParseBase32),
            },
        }
    }

    /// Transforms a `Secret::Base32` into a `Secret::Plain`
    pub fn as_plain(&self) -> Result<Self, SecretParseError> {
        match self {
            Secret::Plain(_) => Ok(self.clone()),
            Secret::Base32(s) => match base32::decode(Alphabet::RFC4648 { padding: false }, s) {
                Some(buf) => match String::from_utf8(buf) {
                    Ok(str) => Ok(Secret::Plain(str)),
                    Err(e) => Err(SecretParseError::Utf8Error(e)),
                },
                None => Err(SecretParseError::ParseBase32),
            },
        }
    }

    /// Transforms a `Secret::Plain` into a `Secret::Base32`
    pub fn as_base32(&self) -> Self {
        match self {
            Secret::Plain(s) => Secret::Base32(base32::encode(
                Alphabet::RFC4648 { padding: false },
                s.as_ref(),
            )),
            Secret::Base32(_) => self.clone(),
        }
    }

    /// ⚠️ requires feature `gen_secret`
    ///
    /// Generate a CSPRNG alpha-numeric string of length `size`
    #[cfg(feature = "gen_secret")]
    pub fn generate_secret(size: usize) -> Secret {
        use rand::distributions::{Alphanumeric, DistString};
        Secret::Plain(Alphanumeric.sample_string(&mut rand::thread_rng(), size))
    }

    /// ⚠️ requires feature `gen_secret`
    ///
    /// Generate a CSPRNG alpha-numeric string of length 20,
    /// the recomended size from [rfc-4226](https://tools.ietf.org/html/rfc4226)
    ///
    /// > The length of the shared secret MUST be at least 128 bits.
    /// > This document RECOMMENDs a shared secret length of 160 bits.
    #[cfg(feature = "gen_secret")]
    pub fn generate_rfc_secret() -> Secret {
        Secret::generate_secret(20)
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Plain(s) => write!(f, "{}", s),
            Secret::Base32(s) => write!(f, "{}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    const PLAIN: &str = "plain-string-secret-123";
    const BASE32: &str = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    const BYTES: [u8; 23] = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];

    #[test]
    fn secret_convert_base32_plain() {
        let plain_str = String::from(PLAIN);
        let base32_str = String::from(BASE32);
        let secret_plain = Secret::Plain(plain_str.clone());
        let secret_base32 = Secret::Base32(base32_str.clone());

        assert_eq!(&secret_plain.as_base32(), &secret_base32);
        assert_eq!(&secret_plain.as_plain().unwrap(), &secret_plain);

        assert_eq!(&secret_base32.as_plain().unwrap(), &secret_plain);
        assert_eq!(&secret_base32.as_base32(), &secret_base32);
    }

    #[test]
    fn secret_as_bytes() {
        let plain_str = String::from(PLAIN);
        let base32_str = String::from(BASE32);
        assert_eq!(Secret::Plain(plain_str).as_bytes().unwrap(), BYTES.to_vec());
        assert_eq!(Secret::Base32(base32_str).as_bytes().unwrap(), BYTES.to_vec());
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_secret() {
        match Secret::generate_secret(10) {
            Secret::Plain(secret) => assert_eq!(secret.len(), 10),
            Secret::Base32(_) => panic!("should be plain"),
        }
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_rfc_secret() {
        match Secret::generate_rfc_secret() {
            Secret::Plain(secret) => assert_eq!(secret.len(), 20),
            Secret::Base32(_) => panic!("should be plain"),
        }
    }
}
