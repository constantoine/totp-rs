use hmac::Mac;
type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

use std::fmt;

/// Alphabet for Steam tokens.
#[cfg(feature = "steam")]
pub(super) const STEAM_CHARS: &str = "23456789BCDFGHJKMNPQRTVWXY";

/// Algorithm enum holds the three standards algorithms for TOTP as per the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum Algorithm {
    /// HMAC-SHA1 is the default algorithm of most TOTP implementations.
    /// Some will outright silently ignore the algorithm parameter to force using SHA1, leading to confusion.
    SHA1,
    /// HMAC-SHA256. Supported in theory according to [yubico](https://docs.yubico.com/yesdk/users-manual/application-oath/uri-string-format.html).
    /// Ignored in practice by most.
    SHA256,
    /// HMAC-SHA512. Supported in theory according to [yubico](https://docs.yubico.com/yesdk/users-manual/application-oath/uri-string-format.html).
    /// Ignored in practice by most.
    SHA512,
    #[cfg(feature = "steam")]
    #[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
    /// Steam TOTP token algorithm.
    Steam,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::SHA1
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::SHA1 => f.write_str("SHA1"),
            Algorithm::SHA256 => f.write_str("SHA256"),
            Algorithm::SHA512 => f.write_str("SHA512"),
            #[cfg(feature = "steam")]
            Algorithm::Steam => f.write_str("SHA1"),
        }
    }
}

impl Algorithm {
    fn hash<D>(mut digest: D, data: &[u8]) -> Vec<u8>
    where
        D: Mac,
    {
        digest.update(data);
        digest.finalize().into_bytes().to_vec()
    }

    pub(crate) fn sign(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::SHA1 => Algorithm::hash(HmacSha1::new_from_slice(key).unwrap(), data),
            Algorithm::SHA256 => Algorithm::hash(HmacSha256::new_from_slice(key).unwrap(), data),
            Algorithm::SHA512 => Algorithm::hash(HmacSha512::new_from_slice(key).unwrap(), data),
            #[cfg(feature = "steam")]
            Algorithm::Steam => Algorithm::hash(HmacSha1::new_from_slice(key).unwrap(), data),
        }
    }
}
