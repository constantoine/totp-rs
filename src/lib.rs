//! This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! Default features are kept as low-dependency as possible to ensure small binaries and short compilation time
//!
//! Be aware that some authenticator apps will accept the `SHA256`
//! and `SHA512` algorithms but silently fallback to `SHA1` which will
//! make the `check()` function fail due to mismatched algorithms.
//!
//! Use the `SHA1` algorithm to avoid this problem.
//!
//! # Examples
//!
//! ```rust
//! # #[cfg(feature = "otpauth")] {
//! use std::time::SystemTime;
//! use totp_rs::{Algorithm, Totp, Secret};
//!
//! let totp = Totp::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     Secret::Raw("TestSecretSuperSecret".as_bytes().to_vec()).to_bytes().unwrap(),
//!     Some("Github".to_string()),
//!     "constantoine@github.com".to_string(),
//! ).unwrap();
//! let token = totp.generate_current().unwrap();
//! println!("{}", token);
//! # }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "qr")] {
//! use totp_rs::{Algorithm, Totp};
//!
//! let totp = Totp::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     "supersecret_topsecret".as_bytes().to_vec(),
//!     Some("Github".to_string()),
//!     "constantoine@github.com".to_string(),
//! ).unwrap();
//! let url = totp.to_url();
//! println!("{}", url);
//! let code = totp.to_qr_base64().unwrap();
//! println!("{}", code);
//! # }
//! ```

// enable `doc_cfg` feature for `docs.rs`.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod algorithm;
mod builder;
mod custom_providers;
mod error;
mod rfc;
mod secret;

#[cfg(feature = "otpauth")]
mod url;

#[cfg(feature = "qr")]
pub use qrcodegen_image;

pub use builder::Builder;
pub use algorithm::Algorithm;
pub use error::TotpError;
pub use rfc::Rfc6238;
pub use secret::{Secret, SecretParseError};

use constant_time_eq::constant_time_eq;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use core::fmt;

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

fn system_time() -> Result<u64, SystemTimeError> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(t)
}

/// TOTP holds informations as to how to generate an auth code and validate it. Its [secret](struct.Totp.html#structfield.secret) field is sensitive data, treat it accordingly
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Totp {
    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub(crate) algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits
    pub(crate) digits: u32,
    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid
    pub(crate) skew: u32,
    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    pub(crate) step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended
    ///
    /// non-encoded value
    pub(crate) secret: Vec<u8>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    pub(crate) issuer: Option<String>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    pub(crate) account_name: String,
}

impl PartialEq for Totp {
    /// Will not check for issuer and account_name equality
    /// As they aren't taken in account for token generation/token checking
    fn eq(&self, other: &Self) -> bool {
        if self.algorithm != other.algorithm {
            return false;
        }
        if self.digits != other.digits {
            return false;
        }
        if self.skew != other.skew {
            return false;
        }
        if self.step != other.step {
            return false;
        }
        constant_time_eq(self.secret.as_ref(), other.secret.as_ref())
    }
}

#[cfg(feature = "otpauth")]
impl core::fmt::Display for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "digits: {}; step: {}; alg: {}; issuer: <{}>({})",
            self.digits,
            self.step,
            self.algorithm,
            self.issuer.clone().unwrap_or_else(|| "None".to_string()),
            self.account_name
        )
    }
}

#[cfg(not(feature = "otpauth"))]
impl core::fmt::Display for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "digits: {}; step: {}; alg: {}",
            self.digits, self.step, self.algorithm,
        )
    }
}

#[cfg(all(feature = "gen_secret", not(feature = "otpauth")))]
// because `Default` is implemented regardless of `otpauth` feature we don't specify it here
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Totp {
    fn default() -> Self {
        return Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::generate_secret().to_bytes().unwrap(),
        )
        .unwrap();
    }
}

#[cfg(all(feature = "gen_secret", feature = "otpauth"))]
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Totp {
    fn default() -> Self {
        Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::generate_secret().to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .unwrap()
    }
}

impl Totp {
    #[cfg(feature = "otpauth")]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.Totp.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    /// * `digits`: MUST be between 6 & 8
    /// * `secret`: Must have bitsize of at least 128
    /// * `account_name`: Must not contain `:`
    /// * `issuer`: Must not contain `:`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, Totp, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap(), None, "".to_string()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if the `digit` or `secret` size is invalid or if `issuer` or `label` contain the character ':'
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Vec<u8>,
        issuer: Option<String>,
        account_name: String,
    ) -> Result<Totp, TotpError> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret.as_ref())?;
        if issuer.is_some() && issuer.as_ref().unwrap().contains(':') {
            return Err(TotpError::InvalidIssuer {
                value: issuer.as_ref().unwrap().to_string(),
            });
        }
        if account_name.contains(':') {
            return Err(TotpError::InvalidAccountName {
                value: account_name,
            });
        }
        Ok(Self::new_unchecked(
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        ))
    }

    #[cfg(feature = "otpauth")]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.Totp.html#fields) for reference as to how to choose those values. This is unchecked and does not check the `digits` and `secret` size
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, Totp, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = Totp::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap(), None, "".to_string());
    /// ```
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Vec<u8>,
        issuer: Option<String>,
        account_name: String,
    ) -> Totp {
        Totp {
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        }
    }

    #[cfg(not(feature = "otpauth"))]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.Totp.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    /// * `digits`: MUST be between 6 & 8
    /// * `secret`: Must have bitsize of at least 128
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, Totp, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if the `digit` or `secret` size is invalid
    pub fn new(
        algorithm: Algorithm,
        digits: u32,
        skew: u32,
        step: u64,
        secret: Vec<u8>,
    ) -> Result<Totp, TotpError> {
        crate::rfc::assert_digits(digits)?;
        crate::rfc::assert_secret_length(secret.as_ref())?;
        Ok(Self::new_unchecked(algorithm, digits, skew, step, secret))
    }

    #[cfg(not(feature = "otpauth"))]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.Totp.html#fields) for reference as to how to choose those values. This is unchecked and does not check the `digits` and `secret` size
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, Totp, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = Totp::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap());
    /// ```
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: u32,
        skew: u32,
        step: u64,
        secret: Vec<u8>,
    ) -> Totp {
        Totp {
            algorithm,
            digits,
            skew,
            step,
            secret,
        }
    }

    /// Will create a new instance of TOTP from the given [Rfc6238](struct.Rfc6238.html) struct
    ///
    /// # Errors
    ///
    /// Will return an error in case issuer or label contain the character ':'
    pub fn from_rfc6238(rfc: Rfc6238) -> Result<Totp, TotpError> {
        Totp::try_from(rfc)
    }

    /// Will sign the given timestamp
    pub fn sign(&self, time: u64) -> Vec<u8> {
        self.algorithm.sign(
            self.secret.as_ref(),
            (time / self.step).to_be_bytes().as_ref(),
        )
    }

    /// Will generate a token given the provided timestamp in seconds
    pub fn generate(&self, time: u64) -> String {
        let result: &[u8] = &self.sign(time);
        let offset = (result.last().unwrap() & 15) as usize;
        #[allow(unused_mut)]
        let mut result =
            u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;

        match self.algorithm {
            Algorithm::SHA1 | Algorithm::SHA256 | Algorithm::SHA512 => format!(
                "{1:00$}",
                self.digits as usize,
                result % 10_u32.pow(self.digits)
            ),
            #[cfg(feature = "steam")]
            Algorithm::Steam => (0..self.digits)
                .map(|_| {
                    let c = STEAM_CHARS
                        .chars()
                        .nth(result as usize % STEAM_CHARS.len())
                        .unwrap();
                    result /= STEAM_CHARS.len() as u32;
                    c
                })
                .collect(),
        }
    }

    /// Returns the timestamp of the first second for the next step
    /// given the provided timestamp in seconds
    pub fn next_step(&self, time: u64) -> u64 {
        let step = time / self.step;

        (step + 1) * self.step
    }

    /// Returns the timestamp of the first second of the next step
    /// According to system time
    pub fn next_step_current(&self) -> Result<u64, SystemTimeError> {
        let t = system_time()?;
        Ok(self.next_step(t))
    }

    /// Give the ttl (in seconds) of the current token
    pub fn ttl(&self) -> Result<u64, SystemTimeError> {
        let t = system_time()?;
        Ok(self.step - (t % self.step))
    }

    /// Generate a token from the current system time
    pub fn generate_current(&self) -> Result<String, SystemTimeError> {
        let t = system_time()?;
        Ok(self.generate(t))
    }

    /// Will check if token is valid given the provided timestamp in seconds, accounting [skew](struct.Totp.html#structfield.skew)
    pub fn check(&self, token: &str, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..(self.skew as u16) * 2 + 1 {
            let step_time = (basestep + (i as u64)) * self.step;

            if constant_time_eq(self.generate(step_time).as_bytes(), token.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Will check if token is valid by current system time, accounting [skew](struct.Totp.html#structfield.skew)
    pub fn check_current(&self, token: &str) -> Result<bool, SystemTimeError> {
        let t = system_time()?;
        Ok(self.check(token, t))
    }

    /// Will return the base32 representation of the secret, which might be useful when users want to manually add the secret to their authenticator
    pub fn to_secret_base32(&self) -> String {
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            self.secret.as_ref(),
        )
    }
}

#[cfg(feature = "qr")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
impl Totp {
    #[deprecated(
        since = "5.3.0",
        note = "to_qr was forcing the use of png as a base64. Use to_qr_base64 or to_qr_png instead. Will disappear in 6.0."
    )]
    pub fn to_qr(&self) -> Result<String, String> {
        let url = self.to_url();
        qrcodegen_image::draw_base64(&url)
    }

    /// Will return a qrcode to automatically add a TOTP as a base64 string. Needs feature `qr` to be enabled!
    /// Result will be in the form of a string containing a base64-encoded png, which you can embed in HTML without needing
    /// To store the png as a file.
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code.
    /// This would require the to_url method to generate an url bigger than 2000 characters,
    /// Which would be too long for some browsers anyway.
    ///
    /// It will also return an error in case it can't encode the qr into a png.
    /// This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    pub fn to_qr_base64(&self) -> Result<String, String> {
        let url = self.to_url();
        qrcodegen_image::draw_base64(&url)
    }

    /// Will return a qrcode to automatically add a TOTP as a byte array. Needs feature `qr` to be enabled!
    /// Result will be in the form of a png file as bytes.
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code.
    /// This would require the to_url method to generate an url bigger than 2000 characters,
    /// Which would be too long for some browsers anyway.
    ///
    /// It will also return an error in case it can't encode the qr into a png.
    /// This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    pub fn to_qr_png(&self) -> Result<Vec<u8>, String> {
        let url = self.to_url();
        qrcodegen_image::draw_png(&url)
    }
}

#[cfg(all(test, not(feature = "otpauth")))]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "gen_secret")]
    fn default_values() {
        let totp = Totp::default();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30)
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_algo() {
        let reference =
            Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = Totp::new(Algorithm::SHA256, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_digits() {
        let reference =
            Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = Totp::new(Algorithm::SHA1, 8, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_skew() {
        let reference =
            Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = Totp::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_step() {
        let reference =
            Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = Totp::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_secret() {
        let reference =
            Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretDifferentSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn returns_base32() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(
            totp.to_secret_base32().as_str(),
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "659761");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token_current() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            totp.generate(time).as_str(),
            totp.generate_current().unwrap()
        );
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generates_token_sha256() {
        let totp = Totp::new(Algorithm::SHA256, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "076417");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generates_token_sha512() {
        let totp = Totp::new(Algorithm::SHA512, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "473536");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token() {
        let totp = Totp::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.check("659761", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_big_skew() {
        let totp = Totp::new(Algorithm::SHA1, 6, 255, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.check("659761", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_current() {
        let totp = Totp::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp
            .check_current(&totp.generate_current().unwrap())
            .unwrap());
        assert!(!totp.check_current("bogus").unwrap());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_with_skew() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(
            totp.check("174269", 1000) && totp.check("659761", 1000) && totp.check("260393", 1000)
        );
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn next_step() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.next_step(0) == 30);
        assert!(totp.next_step(29) == 30);
        assert!(totp.next_step(30) == 60);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn next_step_current() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        let t = system_time().unwrap();
        assert!(totp.next_step_current().unwrap() == totp.next_step(t));
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use qrcodegen_image::qrcodegen;
        use sha2::{Digest, Sha512};

        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.to_url();
        let qr = qrcodegen::QrCode::encode_text(&url, qrcodegen::QrCodeEcc::Medium)
            .expect("could not generate qr");
        let data = qrcodegen_image::draw_canvas(qr).into_raw();

        // Create hash from image
        let hash_digest = Sha512::digest(data);
        assert_eq!(
            format!("{:x}", hash_digest).as_str(),
            "fbb0804f1e4f4c689d22292c52b95f0783b01b4319973c0c50dd28af23dbbbe663dce4eb05a7959086d9092341cb9f103ec5a9af4a973867944e34c063145328"
        );
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_base64_ok() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let qr = totp.to_qr_base64();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_png_ok() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let qr = totp.to_qr_png();
        assert!(qr.is_ok());
    }
}
