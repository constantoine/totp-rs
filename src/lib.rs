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
//! use totp_rs::{Algorithm, TOTP, Secret};
//!
//! let totp = TOTP::new(
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
//! use totp_rs::{Algorithm, TOTP};
//!
//! let totp = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     "supersecret_topsecret".as_bytes().to_vec(),
//!     Some("Github".to_string()),
//!     "constantoine@github.com".to_string(),
//! ).unwrap();
//! let url = totp.get_url();
//! println!("{}", url);
//! let code = totp.get_qr_base64().unwrap();
//! println!("{}", code);
//! # }
//! ```

// enable `doc_cfg` feature for `docs.rs`.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod custom_providers;
mod rfc;
mod secret;
mod url_error;

#[cfg(feature = "qr")]
pub use qrcodegen_image;

pub use rfc::{Rfc6238, Rfc6238Error};
pub use secret::{Secret, SecretParseError};
pub use url_error::TotpUrlError;

use constant_time_eq::constant_time_eq;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use core::fmt;

#[cfg(feature = "otpauth")]
use url::{Host, Url};

use hmac::Mac;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Alphabet for Steam tokens.
#[cfg(feature = "steam")]
const STEAM_CHARS: &str = "23456789BCDFGHJKMNPQRTVWXY";

/// Algorithm enum holds the three standards algorithms for TOTP as per the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum Algorithm {
    /// HMAC-SHA1 is the default algorithm of most TOTP implementations.
    /// Some will outright ignore the algorithm parameter to force using SHA1, leading to confusion.
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

    fn sign(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::SHA1 => Algorithm::hash(HmacSha1::new_from_slice(key).unwrap(), data),
            Algorithm::SHA256 => Algorithm::hash(HmacSha256::new_from_slice(key).unwrap(), data),
            Algorithm::SHA512 => Algorithm::hash(HmacSha512::new_from_slice(key).unwrap(), data),
            #[cfg(feature = "steam")]
            Algorithm::Steam => Algorithm::hash(HmacSha1::new_from_slice(key).unwrap(), data),
        }
    }
}

fn system_time() -> Result<u64, SystemTimeError> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(t)
}

/// TOTP holds informations as to how to generate an auth code and validate it. Its [secret](struct.TOTP.html#structfield.secret) field is sensitive data, treat it accordingly
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct TOTP {
    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits
    pub digits: usize,
    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid
    pub skew: u8,
    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    pub step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended
    ///
    /// non-encoded value
    pub secret: Vec<u8>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    pub issuer: Option<String>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    pub account_name: String,
}

impl PartialEq for TOTP {
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
impl core::fmt::Display for TOTP {
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
impl core::fmt::Display for TOTP {
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
impl Default for TOTP {
    fn default() -> Self {
        return TOTP::new(
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
impl Default for TOTP {
    fn default() -> Self {
        TOTP::new(
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

impl TOTP {
    #[cfg(feature = "otpauth")]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
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
    /// use totp_rs::{Secret, TOTP, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap(), None, "".to_string()).unwrap();
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
    ) -> Result<TOTP, TotpUrlError> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret.as_ref())?;
        if issuer.is_some() && issuer.as_ref().unwrap().contains(':') {
            return Err(TotpUrlError::Issuer(issuer.as_ref().unwrap().to_string()));
        }
        if account_name.contains(':') {
            return Err(TotpUrlError::AccountName(account_name));
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
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values. This is unchecked and does not check the `digits` and `secret` size
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, TOTP, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap(), None, "".to_string());
    /// ```
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Vec<u8>,
        issuer: Option<String>,
        account_name: String,
    ) -> TOTP {
        TOTP {
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
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    /// * `digits`: MUST be between 6 & 8
    /// * `secret`: Must have bitsize of at least 128
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, TOTP, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if the `digit` or `secret` size is invalid
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Vec<u8>,
    ) -> Result<TOTP, TotpUrlError> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret.as_ref())?;
        Ok(Self::new_unchecked(algorithm, digits, skew, step, secret))
    }

    #[cfg(not(feature = "otpauth"))]
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values. This is unchecked and does not check the `digits` and `secret` size
    ///
    /// # Description
    /// * `secret`: expect a non-encoded value, to pass in base32 string use `Secret::Encoded(String)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Secret, TOTP, Algorithm};
    /// let secret = Secret::Encoded("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG".to_string());
    /// let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap());
    /// ```
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: Vec<u8>,
    ) -> TOTP {
        TOTP {
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
    pub fn from_rfc6238(rfc: Rfc6238) -> Result<TOTP, TotpUrlError> {
        TOTP::try_from(rfc)
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
                self.digits,
                result % 10_u32.pow(self.digits as u32)
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

    /// Will check if token is valid given the provided timestamp in seconds, accounting [skew](struct.TOTP.html#structfield.skew)
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

    /// Will check if token is valid by current system time, accounting [skew](struct.TOTP.html#structfield.skew)
    pub fn check_current(&self, token: &str) -> Result<bool, SystemTimeError> {
        let t = system_time()?;
        Ok(self.check(token, t))
    }

    /// Will return the base32 representation of the secret, which might be useful when users want to manually add the secret to their authenticator
    pub fn get_secret_base32(&self) -> String {
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            self.secret.as_ref(),
        )
    }

    /// Generate a TOTP from the standard otpauth URL
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<TOTP, TotpUrlError> {
        let (algorithm, digits, skew, step, secret, issuer, account_name) =
            Self::parts_from_url(url)?;
        TOTP::new(algorithm, digits, skew, step, secret, issuer, account_name)
    }

    /// Generate a TOTP from the standard otpauth URL, using `TOTP::new_unchecked` internally
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn from_url_unchecked<S: AsRef<str>>(url: S) -> Result<TOTP, TotpUrlError> {
        let (algorithm, digits, skew, step, secret, issuer, account_name) =
            Self::parts_from_url(url)?;
        Ok(TOTP::new_unchecked(
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        ))
    }

    /// Parse the TOTP parts from the standard otpauth URL
    #[cfg(feature = "otpauth")]
    fn parts_from_url<S: AsRef<str>>(
        url: S,
    ) -> Result<(Algorithm, usize, u8, u64, Vec<u8>, Option<String>, String), TotpUrlError> {
        let mut algorithm = Algorithm::SHA1;
        let mut digits = 6;
        let mut step = 30;
        let mut secret = Vec::new();
        let mut issuer: Option<String> = None;
        let mut account_name: String;

        let url = Url::parse(url.as_ref()).map_err(TotpUrlError::Url)?;
        if url.scheme() != "otpauth" {
            return Err(TotpUrlError::Scheme(url.scheme().to_string()));
        }
        match url.host() {
            Some(Host::Domain("totp")) => {}
            #[cfg(feature = "steam")]
            Some(Host::Domain("steam")) => {
                algorithm = Algorithm::Steam;
            }
            _ => {
                return Err(TotpUrlError::Host(url.host().unwrap().to_string()));
            }
        }

        let path = url.path().trim_start_matches('/');
        let path = urlencoding::decode(path)
            .map_err(|_| TotpUrlError::AccountNameDecoding(path.to_string()))?
            .to_string();
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            account_name = parts.1.to_owned();
        } else {
            account_name = path;
        }

        account_name = urlencoding::decode(account_name.as_str())
            .map_err(|_| TotpUrlError::AccountName(account_name.to_string()))?
            .to_string();

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                #[cfg(feature = "steam")]
                "algorithm" if algorithm == Algorithm::Steam => {
                    // Do not change used algorithm if this is Steam
                }
                "algorithm" => {
                    algorithm = match value.as_ref() {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => return Err(TotpUrlError::Algorithm(value.to_string())),
                    }
                }
                "digits" => {
                    digits = value
                        .parse::<usize>()
                        .map_err(|_| TotpUrlError::Digits(value.to_string()))?;
                }
                "period" => {
                    step = value
                        .parse::<u64>()
                        .map_err(|_| TotpUrlError::Step(value.to_string()))?;
                }
                "secret" => {
                    secret = base32::decode(
                        base32::Alphabet::Rfc4648 { padding: false },
                        value.as_ref(),
                    )
                    .ok_or_else(|| TotpUrlError::Secret(value.to_string()))?;
                }
                #[cfg(feature = "steam")]
                "issuer" if value.to_lowercase() == "steam" => {
                    algorithm = Algorithm::Steam;
                    digits = 5;
                    issuer = Some(value.into());
                }
                "issuer" => {
                    let param_issuer: String = value.into();
                    if issuer.is_some() && param_issuer.as_str() != issuer.as_ref().unwrap() {
                        return Err(TotpUrlError::IssuerMistmatch(
                            issuer.as_ref().unwrap().to_string(),
                            param_issuer,
                        ));
                    }
                    issuer = Some(param_issuer);
                    #[cfg(feature = "steam")]
                    if issuer == Some("Steam".into()) {
                        algorithm = Algorithm::Steam;
                    }
                }
                _ => {}
            }
        }

        #[cfg(feature = "steam")]
        if algorithm == Algorithm::Steam {
            digits = 5;
            step = 30;
            issuer = Some("Steam".into());
        }

        if secret.is_empty() {
            return Err(TotpUrlError::Secret("".to_string()));
        }

        Ok((algorithm, digits, 1, step, secret, issuer, account_name))
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    ///
    /// Label and issuer will be URL-encoded if needed be
    /// Secret will be base 32'd without padding, as per RFC.
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn get_url(&self) -> String {
        #[allow(unused_mut)]
        let mut host = "totp";
        #[cfg(feature = "steam")]
        if self.algorithm == Algorithm::Steam {
            host = "steam";
        }
        let account_name = urlencoding::encode(self.account_name.as_str()).to_string();
        let mut params = vec![format!("secret={}", self.get_secret_base32())];
        if self.digits != 6 {
            params.push(format!("digits={}", self.digits));
        }
        if self.algorithm != Algorithm::SHA1 {
            params.push(format!("algorithm={}", self.algorithm));
        }
        let label = if let Some(issuer) = &self.issuer {
            let issuer = urlencoding::encode(issuer);
            params.push(format!("issuer={}", issuer));
            format!("{}:{}", issuer, account_name)
        } else {
            account_name
        };
        if self.step != 30 {
            params.push(format!("period={}", self.step));
        }

        format!("otpauth://{}/{}?{}", host, label, params.join("&"))
    }
}

#[cfg(feature = "qr")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
impl TOTP {
    #[deprecated(
        since = "5.3.0",
        note = "get_qr was forcing the use of png as a base64. Use get_qr_base64 or get_qr_png instead. Will disappear in 6.0."
    )]
    pub fn get_qr(&self) -> Result<String, String> {
        let url = self.get_url();
        qrcodegen_image::draw_base64(&url)
    }

    /// Will return a qrcode to automatically add a TOTP as a base64 string. Needs feature `qr` to be enabled!
    /// Result will be in the form of a string containing a base64-encoded png, which you can embed in HTML without needing
    /// To store the png as a file.
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code.
    /// This would require the get_url method to generate an url bigger than 2000 characters,
    /// Which would be too long for some browsers anyway.
    ///
    /// It will also return an error in case it can't encode the qr into a png.
    /// This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    pub fn get_qr_base64(&self) -> Result<String, String> {
        let url = self.get_url();
        qrcodegen_image::draw_base64(&url)
    }

    /// Will return a qrcode to automatically add a TOTP as a byte array. Needs feature `qr` to be enabled!
    /// Result will be in the form of a png file as bytes.
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code.
    /// This would require the get_url method to generate an url bigger than 2000 characters,
    /// Which would be too long for some browsers anyway.
    ///
    /// It will also return an error in case it can't encode the qr into a png.
    /// This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    pub fn get_qr_png(&self) -> Result<Vec<u8>, String> {
        let url = self.get_url();
        qrcodegen_image::draw_png(&url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "gen_secret")]
    fn default_values() {
        let totp = TOTP::default();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30)
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn new_wrong_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github:".to_string()),
            "constantoine@github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(totp.unwrap_err(), TotpUrlError::Issuer(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn new_wrong_account_name() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine:github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(totp.unwrap_err(), TotpUrlError::AccountName(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn new_wrong_account_name_no_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            None,
            "constantoine:github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(totp.unwrap_err(), TotpUrlError::AccountName(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn comparison_ok() {
        let reference = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let test = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_algo() {
        let reference =
            TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_digits() {
        let reference =
            TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 8, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_skew() {
        let reference =
            TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_step() {
        let reference =
            TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn comparison_different_secret() {
        let reference =
            TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretDifferentSecret".into()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha1_without_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            None,
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(
            url.as_str(),
            "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha1() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha256() {
        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha512() {
        let totp = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA512&issuer=Github");
    }

    #[test]
    #[cfg(all(feature = "otpauth", feature = "gen_secret"))]
    fn ttl() {
        let secret = Secret::default();
        let totp_rfc = Rfc6238::with_defaults(secret.to_bytes().unwrap()).unwrap();
        let totp = TOTP::from_rfc6238(totp_rfc);
        assert!(totp.is_ok());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn ttl_ok() {
        let totp = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert!(totp.ttl().is_ok());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn returns_base32() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(
            totp.get_secret_base32().as_str(),
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "659761");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
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
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "076417");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generates_token_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "473536");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.check("659761", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_big_skew() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 255, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.check("659761", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp
            .check_current(&totp.generate_current().unwrap())
            .unwrap());
        assert!(!totp.check_current("bogus").unwrap());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn checks_token_with_skew() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretSuperSecret".into()).unwrap();
        assert!(
            totp.check("174269", 1000) && totp.check("659761", 1000) && totp.check("260393", 1000)
        );
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn next_step() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        assert!(totp.next_step(0) == 30);
        assert!(totp.next_step(29) == 30);
        assert!(totp.next_step(30) == 60);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn next_step_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecretSuperSecret".into()).unwrap();
        let t = system_time().unwrap();
        assert!(totp.next_step_current().unwrap() == totp.next_step(t));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_err() {
        assert!(TOTP::from_url("otpauth://hotp/123").is_err());
        assert!(TOTP::from_url("otpauth://totp/GitHub:test").is_err());
        assert!(TOTP::from_url(
            "otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256"
        )
        .is_err());
        assert!(TOTP::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").is_err())
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_default() {
        let totp =
            TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
                .unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query_sha512() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA512").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA512);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_to_url() {
        let totp = TOTP::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_unknown_param() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256&foo=bar").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_issuer_special() {
        let totp = TOTP::from_url("otpauth://totp/Github%40:constantoine%40github.com?issuer=Github%40&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github@".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github@");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_account_name_issuer() {
        let totp = TOTP::from_url("otpauth://totp/Github:constantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_account_name_issuer_encoded() {
        let totp = TOTP::from_url("otpauth://totp/Github%3Aconstantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query_issuer() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
        assert_eq!(totp.issuer.as_ref().unwrap(), "GitHub");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_wrong_scheme() {
        let totp = TOTP::from_url("http://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpUrlError::Scheme(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_wrong_algo() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=MD5");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpUrlError::Algorithm(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query_different_issuers() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=Gitlab&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpUrlError::IssuerMistmatch(_, _)
        ));
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use qrcodegen_image::qrcodegen;
        use sha2::{Digest, Sha512};

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
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
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let qr = totp.get_qr_base64();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_png_ok() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let qr = totp.get_qr_png();
        assert!(qr.is_ok());
    }
}
