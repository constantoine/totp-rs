use crate::Algorithm;
use crate::TotpUrlError;
use crate::TOTP;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

/// Data is not compliant to [rfc-6238](https://tools.ietf.org/html/rfc6238)
#[derive(Debug, Eq, PartialEq)]
pub enum Rfc6238Error {
    /// Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code
    InvalidDigits,
    /// The length of the shared secret MUST be at least 128 bits
    SecretTooSmall,
}

impl std::fmt::Display for Rfc6238Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rfc6238Error::InvalidDigits => write!(
                f,
                "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code"
            ),
            Rfc6238Error::SecretTooSmall => write!(
                f,
                "The length of the shared secret MUST be at least 128 bits"
            ),
        }
    }
}

pub fn assert_digits(digits: &usize) -> Result<(), Rfc6238Error> {
    if !(&6..=&8).contains(&digits) {
        Err(Rfc6238Error::InvalidDigits)
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
///     "totp-sercret-123"
/// ).unwrap();
///
/// // optional, set digits, issuer, account_name
/// rfc.digits(8).unwrap();
/// rfc.issuer("issuer".to_string());
/// rfc.account_name("user-account".to_string());
///
/// let totp = TOTP::from_rfc6238(rfc).unwrap();
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Rfc6238<T = Vec<u8>> {
    /// SHA-1
    algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits
    digits: usize,
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1.
    skew: u8,
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended
    secret: T,
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    issuer: Option<String>,
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    account_name: String,
}

impl<T: AsRef<[u8]>> Rfc6238<T> {
    /// Create an [rfc-6238](https://tools.ietf.org/html/rfc6238) compliant set of options that can be turned into a [TOTP](struct.TOTP.html)
    ///
    /// # Errors
    ///
    /// will return a [Rfc6238Error](enum.Rfc6238Error.html) when
    /// - `digits` is lower than 6 or higher than 8
    /// - `secret` is smaller than 128 bits (16 characters)
    pub fn new(
        digits: usize,
        secret: T,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<Rfc6238<T>, Rfc6238Error> {
        assert_digits(&digits)?;
        if secret.as_ref().len() < 16 {
            Err(Rfc6238Error::SecretTooSmall)
        } else {
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
    }

    /// Create an [rfc-6238](https://tools.ietf.org/html/rfc6238) compliant set of options that can be turned into a [TOTP](struct.TOTP.html),
    /// with a default value of 6 for `digits`, None `issuer` and an empty account
    ///
    /// # Errors
    ///
    /// will return a [Rfc6238Error](enum.Rfc6238Error.html) when
    /// - `digits` is lower than 6 or higher than 8
    /// - `secret` is smaller than 128 bits (16 characters)
    pub fn with_defaults(secret: T) -> Result<Rfc6238<T>, Rfc6238Error> {
        Rfc6238::new(6, secret, None, "".to_string())
    }

    /// Set the `digits`
    pub fn digits(&mut self, value:usize) -> Result<(), Rfc6238Error> {
        assert_digits(&value)?;
        self.digits = value;
        Ok(())
    }

    /// Set the `issuer`
    pub fn issuer(&mut self, value: String) {
        self.issuer = Some(value);
    }

    /// Seet the `account_name`
    pub fn account_name(&mut self, value: String) {
        self.account_name = value;
    }
}

impl<T: AsRef<[u8]>> TryFrom<Rfc6238<T>> for TOTP<T> {
    type Error = TotpUrlError;

    /// Try to create a [TOTP](struct.TOTP.html) from a [Rfc6238](struct.Rfc6238.html) config
    fn try_from(rfc: Rfc6238<T>) -> Result<Self, Self::Error> {
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
    use crate::TotpUrlError;

    use super::{Rfc6238, Rfc6238Error, TOTP};

    const GOOD_SECRET: &str = "01234567890123456789";
    const ISSUER: Option<&str> = None;
    const ACCOUNT: &str = "valid-account";
    const INVALID_ACCOUNT: &str = ":invalid-account";

    #[test]
    fn new_rfc_digits() {
        for x in 0..=20 {
            let rfc = Rfc6238::new(
                x,
                GOOD_SECRET.to_string(),
                ISSUER.map(str::to_string),
                ACCOUNT.to_string(),
            );
            if x < 6 || x > 8 {
                assert!(rfc.is_err());
                assert_eq!(rfc.unwrap_err(), Rfc6238Error::InvalidDigits)
            } else {
                assert!(rfc.is_ok());
            }
        }
    }

    #[test]
    fn new_rfc_secret() {
        let mut secret = String::from("");
        for _ in 0..=20 {
            secret = format!("{}{}", secret, "0");
            let rfc = Rfc6238::new(
                6,
                secret.clone(),
                ISSUER.map(str::to_string),
                ACCOUNT.to_string(),
            );
            let rfc_default = Rfc6238::with_defaults(secret.clone());
            if secret.len() < 16 {
                assert!(rfc.is_err());
                assert_eq!(rfc.unwrap_err(), Rfc6238Error::SecretTooSmall);
                assert!(rfc_default.is_err());
                assert_eq!(rfc_default.unwrap_err(), Rfc6238Error::SecretTooSmall);
            } else {
                assert!(rfc.is_ok());
                assert!(rfc_default.is_ok());
            }
        }
    }

    #[test]
    fn rfc_to_totp_ok() {
        let rfc = Rfc6238::new(
            8,
            GOOD_SECRET.to_string(),
            ISSUER.map(str::to_string),
            ACCOUNT.to_string(),
        )
        .unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_ok());
        let otp = totp.unwrap();
        assert_eq!(&otp.secret, GOOD_SECRET);
        assert_eq!(otp.algorithm, crate::Algorithm::SHA1);
        assert_eq!(&otp.account_name, ACCOUNT);
        assert_eq!(otp.digits, 8);
        assert_eq!(otp.issuer, ISSUER.map(str::to_string));
        assert_eq!(otp.skew, 1);
        assert_eq!(otp.step, 30)
    }

    #[test]
    fn rfc_to_totp_fail() {
        let rfc = Rfc6238::new(
            8,
            GOOD_SECRET.to_string(),
            ISSUER.map(str::to_string),
            INVALID_ACCOUNT.to_string(),
        )
        .unwrap();
        let totp = TOTP::try_from(rfc);
        assert!(totp.is_err());
        assert_eq!(totp.unwrap_err(), TotpUrlError::AccountName)
    }

    #[test]
    fn rfc_with_default_set_values() {
        let new_account = "new-account";
        let new_issuer = String::from("new-issuer");
        let mut rfc = Rfc6238::with_defaults(GOOD_SECRET.to_string()).unwrap();
        rfc.issuer(new_issuer.clone());
        assert_eq!(rfc.issuer, Some(new_issuer));
        rfc.account_name(new_account.to_string());
        assert_eq!(rfc.account_name, new_account.to_string());
        let fail = rfc.digits(4);
        assert!(fail.is_err());
        assert_eq!(fail.unwrap_err(), Rfc6238Error::InvalidDigits);
        assert_eq!(rfc.digits, 6);
        let ok = rfc.digits(8);
        assert!(ok.is_ok());
        assert_eq!(rfc.digits, 8)
    }
}
