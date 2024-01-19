#[cfg(feature = "steam")]
use crate::{Algorithm, TOTP};

#[cfg(feature = "steam")]
#[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
impl TOTP {
    #[cfg(feature = "otpauth")]
    /// Will create a new instance of TOTP using the Steam algorithm with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, TOTP};
    /// let secret = Secret::Encoded("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".into());
    /// let totp = TOTP::new_steam(secret.to_bytes().unwrap(), "username".into());
    /// ```
    pub fn new_steam(secret: Vec<u8>, account_name: String) -> TOTP {
        Self::new_unchecked(
            Algorithm::Steam,
            5,
            1,
            30,
            secret,
            Some("Steam".into()),
            account_name,
        )
    }

    #[cfg(not(feature = "otpauth"))]
    /// Will create a new instance of TOTP using the Steam algorithm with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, TOTP};
    /// let secret = Secret::Encoded("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".to_string());
    /// let totp = TOTP::new_steam(secret.to_bytes().unwrap());
    /// ```
    pub fn new_steam(secret: Vec<u8>) -> TOTP {
        Self::new_unchecked(Algorithm::Steam, 5, 1, 30, secret)
    }
}

#[cfg(all(test, feature = "steam"))]
mod test {
    #[cfg(feature = "otpauth")]
    use super::*;

    #[test]
    #[cfg(feature = "otpauth")]
    fn get_url_steam() {
        let totp = TOTP::new_steam("TestSecretSuperSecret".into(), "constantoine".into());
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://steam/Steam:constantoine?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=5&algorithm=SHA1&issuer=Steam");
    }
}
