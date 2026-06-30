use core::fmt;
use core::str::FromStr;
use hmac::Mac;

#[cfg(feature = "alloc")]
use alloc::string::String;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Algorithm enum holds the three standards algorithms for TOTP as per the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    all(feature = "serde", feature = "alloc"),
    serde(try_from = "String", into = "String")
)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC-SHA1 is the default algorithm of most TOTP implementations.
    /// Some will outright silently ignore the algorithm parameter to force using SHA1, leading to confusion.
    #[default]
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

impl Algorithm {
    /// Returns a name for this algorithm.
    pub const fn as_str(&self) -> &str {
        match self {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
            #[cfg(feature = "steam")]
            Algorithm::Steam => "STEAM",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<Algorithm> for String {
    fn from(value: Algorithm) -> Self {
        value.as_str().into()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<String> for Algorithm {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl FromStr for Algorithm {
    type Err = UnsupportedAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("SHA1") {
            Ok(Self::SHA1)
        } else if s.eq_ignore_ascii_case("SHA256") {
            Ok(Self::SHA256)
        } else if s.eq_ignore_ascii_case("SHA512") {
            Ok(Self::SHA512)
        } else {
            #[cfg(feature = "steam")]
            if s.eq_ignore_ascii_case("STEAM") {
                return Ok(Self::Steam);
            }

            Err(UnsupportedAlgorithm {
                #[cfg(feature = "alloc")]
                algorithm: s.into(),
            })
        }
    }
}

impl Algorithm {
    fn hash<D>(key: &[u8], counter: u64) -> hmac::digest::Output<D>
    where
        D: Mac + hmac::digest::KeyInit,
    {
        let mut digest = D::new_from_slice(key).unwrap();
        let data = counter.to_be_bytes();
        digest.update(&data);
        digest.finalize().into_bytes()
    }

    pub(crate) fn sign(&self, key: &[u8], counter: u64) -> impl AsRef<[u8]> {
        match self {
            Algorithm::SHA1 => Signature::SHA1(Algorithm::hash::<HmacSha1>(key, counter)),
            Algorithm::SHA256 => Signature::SHA256(Algorithm::hash::<HmacSha256>(key, counter)),
            Algorithm::SHA512 => Signature::SHA512(Algorithm::hash::<HmacSha512>(key, counter)),
            #[cfg(feature = "steam")]
            Algorithm::Steam => Signature::SHA1(Algorithm::hash::<HmacSha1>(key, counter)),
        }
    }
}

enum Signature {
    SHA1(hmac::digest::Output<HmacSha1>),
    SHA256(hmac::digest::Output<HmacSha256>),
    SHA512(hmac::digest::Output<HmacSha512>),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::SHA1(inner) => inner.as_ref(),
            Signature::SHA256(inner) => inner.as_ref(),
            Signature::SHA512(inner) => inner.as_ref(),
        }
    }
}

#[derive(PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedAlgorithm {
    #[cfg(feature = "alloc")]
    algorithm: String,
}

impl core::fmt::Debug for UnsupportedAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, f)
    }
}

impl core::fmt::Display for UnsupportedAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Unsupported Algorithm")?;

        #[cfg(feature = "alloc")]
        write!(f, ": {}", self.algorithm)?;

        Ok(())
    }
}

impl core::error::Error for UnsupportedAlgorithm {}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{Algorithm, UnsupportedAlgorithm};

    /// We exhaustively test against all algorithms.
    const ALL_ALGORITHMS: &[Algorithm] = &[
        Algorithm::SHA1,
        Algorithm::SHA256,
        Algorithm::SHA512,
        #[cfg(feature = "steam")]
        Algorithm::Steam,
    ];

    #[test]
    fn from_str_unsupported() {
        let algorithm = Algorithm::from_str("not a real algorithm");
        assert!(matches!(algorithm, Err(UnsupportedAlgorithm { .. })));
        let error = algorithm.unwrap_err();
        assert!(format!("{:?}", error).starts_with("Unsupported Algorithm"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn to_string_round_trip() {
        for &alg in ALL_ALGORITHMS {
            let to_string = String::from(alg);
            let from_string = Algorithm::try_from(to_string);
            assert_eq!(from_string, Ok(alg));
        }
    }

    #[test]
    fn signing_test() {
        for &alg in ALL_ALGORITHMS {
            let key = "TestSecretSuperSecret".as_bytes();
            let data = 123456;

            let signature = alg.sign(key, data);

            assert!(!signature.as_ref().is_empty());
        }
    }
}
