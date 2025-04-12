use crate::Algorithm;
use crate::TotpUrlError;
use crate::TOTP;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Error returned when input is not compliant to [rfc-6238](https://tools.ietf.org/html/rfc6238).
#[derive(Debug, Eq, PartialEq)]
pub enum Rfc6238Error {
    /// Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code.
    InvalidDigits(usize),
    /// The length of the shared secret MUST be at least 128 bits.
    SecretTooSmall(usize),
}

impl std::error::Error for Rfc6238Error {}

impl std::fmt::Display for Rfc6238Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rfc6238Error::InvalidDigits(digits) => write!(
                f,
                "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code. {} digits is not allowed",
                digits,
            ),
            Rfc6238Error::SecretTooSmall(bits) => write!(
                f,
                "The length of the shared secret MUST be at least 128 bits. {} bits is not enough",
                bits,
            ),
        }
    }
}

// Check that the number of digits is RFC-compliant.
// (between 6 and 8 inclusive).
pub fn assert_digits(digits: &usize) -> Result<(), Rfc6238Error> {
    if !(&6..=&8).contains(&digits) {
        Err(Rfc6238Error::InvalidDigits(*digits))
    } else {
        Ok(())
    }
}

// Check that the secret is AT LEAST 128 bits long, as per the RFC's requirements.
// It is still RECOMMENDED to have an at least 160 bits long secret.
pub fn assert_secret_length(secret: &[u8]) -> Result<(), Rfc6238Error> {
    if secret.as_ref().len() < 16 {
        Err(Rfc6238Error::SecretTooSmall(secret.as_ref().len() * 8))
    } else {
        Ok(())
    }
}

/// [rfc-6238](https://tools.ietf.org/html/rfc6238) compliant set of options to create a [TOTP](struct.TOTP.html)
///
/// # Example
/// ```
/// use totp_rs::{Rfc6238, TOTP};
///
/// let mut rfc = Rfc6238::with_defaults(
///     "totp-sercret-123".as_bytes().to_vec()
/// ).unwrap();
///
/// // optional, set digits, issuer, account_name
/// rfc.digits(8).unwrap();
///
/// let totp = TOTP::from_rfc6238(rfc).unwrap();
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Rfc6238 {
    /// SHA-1
    algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits.
    digits: usize,
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1.
    skew: u8,
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds.
    step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended.
    secret: Vec<u8>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    issuer: Option<String>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`.
    /// For example, the name of your user's account.
    account_name: String,
}

impl Rfc6238 {
    /// Create an [rfc-6238](https://tools.ietf.org/html/rfc6238) compliant set of options that can be turned into a [TOTP](struct.TOTP.html).
    ///
    /// # Errors
    ///
    /// will return a [Rfc6238Error](enum.Rfc6238Error.html) when
    /// - `digits` is lower than 6 or higher than 8.
    /// - `secret` is smaller than 128 bits (16 characters).
    #[cfg(feature = "otpauth")]
    pub fn new(
        digits: usize,
        secret: Vec<u8>,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<Rfc6238, Rfc6238Error> {
        assert_digits(&digits)?;
        assert_secret_length(secret.as_ref())?;

        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret,
            issuer,
            account_name,
        })
    }
    #[cfg(not(feature = "otpauth"))]
    pub fn new(digits: usize, secret: Vec<u8>) -> Result<Rfc6238, Rfc6238Error> {
        assert_digits(&digits)?;
        assert_secret_length(secret.as_ref())?;

        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret,
        })
    }

    /// Create an [rfc-6238](https://tools.ietf.org/html/rfc6238) compliant set of options that can be turned into a [TOTP](struct.TOTP.html),
    /// with a default value of 6 for `digits`, None `issuer` and an empty account.
    ///
    /// # Errors
    ///
    /// will return a [Rfc6238Error](enum.Rfc6238Error.html) when
    /// - `digits` is lower than 6 or higher than 8.
    /// - `secret` is smaller than 128 bits (16 characters).
    #[cfg(feature = "otpauth")]
    pub fn with_defaults(secret: Vec<u8>) -> Result<Rfc6238, Rfc6238Error> {
        Rfc6238::new(6, secret, Some("".to_string()), "".to_string())
    }

    #[cfg(not(feature = "otpauth"))]
    pub fn with_defaults(secret: Vec<u8>) -> Result<Rfc6238, Rfc6238Error> {
        Rfc6238::new(6, secret)
    }

    /// Set the `digits`.
    pub fn digits(&mut self, value: usize) -> Result<(), Rfc6238Error> {
        assert_digits(&value)?;
        self.digits = value;
        Ok(())
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Set the `issuer`.
    pub fn issuer(&mut self, value: String) {
        self.issuer = Some(value);
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Set the `account_name`.
    pub fn account_name(&mut self, value: String) {
        self.account_name = value;
    }
}

#[cfg(not(feature = "otpauth"))]
impl TryFrom<Rfc6238> for TOTP {
    type Error = TotpUrlError;

    /// Try to create a [TOTP](struct.TOTP.html) from a [Rfc6238](struct.Rfc6238.html) config.
    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        TOTP::new(rfc.algorithm, rfc.digits, rfc.skew, rfc.step, rfc.secret)
    }
}

#[cfg(feature = "otpauth")]
impl TryFrom<Rfc6238> for TOTP {
    type Error = TotpUrlError;

    /// Try to create a [TOTP](struct.TOTP.html) from a [Rfc6238](struct.Rfc6238.html) config.
    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        TOTP::new(
            rfc.algorithm,
            rfc.digits,
            rfc.skew,
            rfc.step,
            rfc.secret,
            rfc.issuer,
            rfc.account_name,
        )
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "otpauth")]
    use crate::TotpUrlError;

    use super::{Rfc6238, TOTP};

    #[cfg(not(feature = "otpauth"))]
    use super::Rfc6238Error;

    #[cfg(not(feature = "otpauth"))]
    use crate::Secret;

    const GOOD_SECRET: &str = "01234567890123456789";
    #[cfg(feature = "otpauth")]
    const ISSUER: Option<&str> = None;
    #[cfg(feature = "otpauth")]
    const ACCOUNT: &str = "valid-account";
    #[cfg(feature = "otpauth")]
    const INVALID_ACCOUNT: &str = ":invalid-account";

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn new_rfc_digits() {
        for x in 0..=20 {
            let rfc = Rfc6238::new(x, GOOD_SECRET.into());
            if !(6..=8).contains(&x) {
                assert!(rfc.is_err());
                assert!(matches!(rfc.unwrap_err(), Rfc6238Error::InvalidDigits(_)));
            } else {
                assert!(rfc.is_ok());
            }
        }
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn new_rfc_secret() {
        let mut secret = String::from("");
        for _ in 0..=20 {
            secret = format!("{}{}", secret, "0");
            let rfc = Rfc6238::new(6, secret.as_bytes().to_vec());
            let rfc_default = Rfc6238::with_defaults(secret.as_bytes().to_vec());
            if secret.len() < 16 {
                assert!(rfc.is_err());
                assert!(matches!(rfc.unwrap_err(), Rfc6238Error::SecretTooSmall(_)));
                assert!(rfc_default.is_err());
                assert!(matches!(
                    rfc_default.unwrap_err(),
                    Rfc6238Error::SecretTooSmall(_)
                ));
            } else {
                assert!(rfc.is_ok());
                assert!(rfc_default.is_ok());
            }
        }
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn rfc_to_totp_ok() {
        let rfc = Rfc6238::new(8, GOOD_SECRET.into()).unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_ok());
        let otp = totp.unwrap();
        assert_eq!(&otp.secret, GOOD_SECRET.as_bytes());
        assert_eq!(otp.algorithm, crate::Algorithm::SHA1);
        assert_eq!(otp.digits, 8);
        assert_eq!(otp.skew, 1);
        assert_eq!(otp.step, 30)
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn rfc_to_totp_ok_2() {
        let rfc = Rfc6238::with_defaults(
            Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string())
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_ok());
        let otp = totp.unwrap();
        assert_eq!(otp.algorithm, crate::Algorithm::SHA1);
        assert_eq!(otp.digits, 6);
        assert_eq!(otp.skew, 1);
        assert_eq!(otp.step, 30)
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn rfc_to_totp_fail() {
        let rfc = Rfc6238::new(
            8,
            GOOD_SECRET.as_bytes().to_vec(),
            ISSUER.map(str::to_string),
            INVALID_ACCOUNT.to_string(),
        )
        .unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_err());
        assert!(matches!(totp.unwrap_err(), TotpUrlError::AccountName(_)))
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn rfc_to_totp_ok() {
        let rfc = Rfc6238::new(
            8,
            GOOD_SECRET.as_bytes().to_vec(),
            ISSUER.map(str::to_string),
            ACCOUNT.to_string(),
        )
        .unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_ok());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn rfc_with_default_set_values() {
        let mut rfc = Rfc6238::with_defaults(GOOD_SECRET.as_bytes().to_vec()).unwrap();
        let ok = rfc.digits(8);
        assert!(ok.is_ok());
        assert_eq!(rfc.account_name, "");
        assert_eq!(rfc.issuer, Some("".to_string()));
        rfc.issuer("Github".to_string());
        rfc.account_name("constantoine".to_string());
        assert_eq!(rfc.account_name, "constantoine");
        assert_eq!(rfc.issuer, Some("Github".to_string()));
        assert_eq!(rfc.digits, 8)
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn rfc_with_default_set_values() {
        let mut rfc = Rfc6238::with_defaults(GOOD_SECRET.as_bytes().to_vec()).unwrap();
        let fail = rfc.digits(4);
        assert!(fail.is_err());
        assert!(matches!(fail.unwrap_err(), Rfc6238Error::InvalidDigits(_)));
        assert_eq!(rfc.digits, 6);
        let ok = rfc.digits(8);
        assert!(ok.is_ok());
        assert_eq!(rfc.digits, 8)
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn digits_error() {
        let error = crate::Rfc6238Error::InvalidDigits(9);
        assert_eq!(
            error.to_string(),
            "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code. 9 digits is not allowed".to_string()
        )
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn secret_length_error() {
        let error = Rfc6238Error::SecretTooSmall(120);
        assert_eq!(
            error.to_string(),
            "The length of the shared secret MUST be at least 128 bits. 120 bits is not enough"
                .to_string()
        )
    }
}
