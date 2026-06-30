//! This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits!
//! Default features are kept as low-dependency as possible to ensure small binaries and short compilation time
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
//! use totp_rs::{Algorithm, Builder, Totp};
//!
//! let secret: Vec<u8> = vec![0; 20]; // You want an actual 20bytes of randomness here.
//!
//! let totp: Totp = Builder::new().
//!     with_algorithm(Algorithm::SHA256).
//!     with_secret(secret).
//!     with_account_name("constantoine@github.com").
//!     with_issuer("Github").
//!     build().
//!     unwrap();
//!
//! let token = totp.generate_current();
//! println!("{}", token);
//! # }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "gen_secret")] {
//! use totp_rs::{Builder, Totp};
//!
//! let totp: Totp = Builder::new().
//!     build().
//!     unwrap();
//!
//! let token = totp.generate_current();
//! println!("{}", token);
//!
//! let secret = totp.secret().as_bytes();
//! # }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "qr")] {
//! use totp_rs::{Algorithm, Builder, Totp};
//!
//! let secret: Vec<u8> = vec![0; 20]; // You want an actual 20bytes of randomness here.
//!
//! let totp: Totp = Builder::new().
//!     with_secret(secret).
//!     with_account_name("constantoine@github.com").
//!     with_issuer("Github").
//!     build().
//!     unwrap();
//!
//! let url = totp.to_url().unwrap();
//! println!("{}", url);
//! let code = totp.to_qr_base64().unwrap();
//! println!("{}", code);
//! # }
//! ```

// enable `doc_cfg` feature for `docs.rs`.
#![cfg_attr(docsrs, feature(doc_cfg))]
// Only allow implicit `use std::prelude::*;` during testing.
#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod algorithm;
mod builder;
mod custom_providers;
mod error;
mod rfc;
mod secret;
mod token;

#[cfg(feature = "otpauth")]
mod url;

#[cfg(feature = "migration")]
mod migration;

pub use algorithm::Algorithm;
pub use builder::Builder;
pub use error::TotpError;
pub use secret::{Secret, SecretParseError};
pub use token::Token;

#[cfg(feature = "migration")]
pub use migration::*;

use core::fmt;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "std")]
fn system_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system time cannot be set before the unix epoch").as_secs()
}

/// TOTP holds informations as to how to generate an auth code and validate it. Its [secret](struct.Totp.html#structfield.secret) field is sensitive data, treat it accordingly
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Totp {
    /// SHA-1 is the most widespread algorithm used, and for totp purposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted.
    /// It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512.
    ///
    /// <div class="warning">Not all clients support other algorithms than SHA-1, and some will silently accept them and use SHA-1 under the hood.</div>
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub(crate) algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscillate between 6 and 8 digits.
    pub(crate) digits: u32,
    /// Number of steps allowed as network delay. A value of 1 would mean a code valid for the step before or the step after current step would be accepted.
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1.
    /// Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid.
    pub(crate) skew: u16,
    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds.
    pub(crate) step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG.
    /// It should be at least 128 bits, but 160 are recommended.
    ///
    /// non-encoded value.
    pub(crate) secret: Secret,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    pub(crate) issuer: Option<alloc::boxed::Box<str>>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    pub(crate) account_name: alloc::boxed::Box<str>,
}

impl Totp {
    /// Get currently used [Algorithm].
    /// See [Builder::with_algorithm] for more details on this value.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get how many digits the generated code will be made of.
    /// See [Builder::with_digits] for more details on this value.
    pub const fn digits(&self) -> u32 {
        self.digits
    }

    /// Get how many steps behind or forward are accepted to account for network skew.
    /// See [Builder::with_skew] for more details on this value.
    pub const fn skew(&self) -> u32 {
        self.skew as u32
    }

    /// Get how many seconds a step lasts.
    /// See [Builder::with_step_duration] for more details on this value.
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Get the name of the issuer who created this Totp.
    /// This value is not always provided.
    /// See [Builder::with_issuer] for more details on this value.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Name of the account the Totp was issued for.
    /// See [Builder::with_account_name] for more details on this value.
    pub const fn account_name(&self) -> &str {
        &self.account_name
    }
}

impl core::fmt::Display for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut succeeded = true;

        succeeded &= write!(
            f,
            "digits: {}; step: {}; alg: {}",
            self.digits, self.step, self.algorithm,
        )
        .is_ok();

        #[cfg(feature = "otpauth")]
        {
            succeeded &= write!(
                f,
                "; issuer: <{}>({})",
                self.issuer.as_deref().unwrap_or("None"),
                self.account_name
            )
            .is_ok();
        }

        succeeded.then_some(()).ok_or(fmt::Error)
    }
}

/// Default as set in [Builder::new].
/// This implementation shall remain, to avoid breaking compatibility.
/// Use [Self::secret] to retrieve the newly generated secret.
#[cfg(feature = "gen_secret")]
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Totp {
    fn default() -> Self {
        use crate::Builder;

        Builder::new().build_noncompliant()
    }
}

impl Totp {
    /// Will sign the given timestamp. Most users will want to interact with [Self::generate].
    pub fn sign(&self, time: u64) -> impl AsRef<[u8]> {
        self.algorithm.sign(self.secret.as_ref(), time / self.step)
    }

    /// Will generate a token given the provided timestamp in seconds.
    pub fn generate(&self, time: u64) -> Token {
        Token::from_signature(
            self.algorithm,
            self.digits.try_into().unwrap(),
            self.sign(time).as_ref(),
        )
    }

    /// Returns the timestamp of the first second for the next step
    /// given the provided timestamp in seconds
    pub fn next_step(&self, time: u64) -> u64 {
        let step = time / self.step;

        (step + 1) * self.step
    }

    /// Returns the timestamp of the first second of the next step
    /// According to system time
    /// 
    /// # Panics
    /// 
    /// Panics if system time is set before Unix Epoch.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn next_step_current(&self) -> u64 {
        self.next_step(system_time())
    }

    /// Give the ttl (in seconds) of the current token
    /// 
    /// # Panics
    /// 
    /// Panics if system time is set before Unix Epoch.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn ttl(&self) -> u64 {
        self.step - (system_time() % self.step)
    }

    /// Generate a token from the current system time
    /// 
    /// # Panics
    /// 
    /// Panics if system time is set before Unix Epoch.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn generate_current(&self) -> Token {
        self.generate(system_time())
    }

    /// Will check if token is valid given the provided timestamp in seconds, accounting [skew](struct.Totp.html#structfield.skew)
    /// If the token is valid, return the matched step.
    ///
    /// <div class="warning">
    /// As per <a href="https://datatracker.ietf.org/doc/html/rfc6238#section-5.2">rfc-6239</a>, a code should only be accepted once.
    /// If a user wants to log in several times in a row (maybe multiple device?) they have to wait for the next time-window.
    /// This library does NOT handle this, and it is the caller's responsibility to make sure a specific step only gets accepted once.
    /// This is the reason why check now returns an optional u64 step-number.
    /// </div>
    pub fn check(&self, token: &str, time: u64) -> Option<u64> {
        let token = Token::try_from_formatted_string(
            self.algorithm,
            self.digits.try_into().unwrap(),
            token,
        )?;

        let origin = time / self.step;
        let mut window = origin.saturating_sub(self.skew as u64)..=(origin + self.skew as u64);
        window.find(|&counter| self.generate(counter * self.step) == token)
    }

    /// Will check if token is valid by current system time, accounting [skew](struct.Totp.html#structfield.skew)
    /// If the token is valid, return the matched step.
    ///
    /// <div class="warning">
    /// As per <a href="https://datatracker.ietf.org/doc/html/rfc6238#section-5.2">rfc-6239</a>, a code should only be accepted once.
    /// If a user wants to log in several times in a row (maybe multiple device?) they have to wait for the next time-window.
    /// This library does NOT handle this, and it is the caller's responsibility to make sure a specific step only gets accepted once.
    /// This is the reason why check now returns an optional u64 step-number.
    /// </div>
    /// 
    /// # Panics
    /// 
    /// Panics if system time is set before Unix Epoch.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn check_current(&self, token: &str) -> Option<u64> {
        self.check(token, system_time())
    }

    /// Provides access to the secret used by this [`Totp`] instance.
    pub const fn secret(&self) -> &Secret {
        &self.secret
    }
}

#[cfg(feature = "qr")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
impl Totp {
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
    pub fn to_qr_base64(&self) -> Result<alloc::string::String, TotpError> {
        let url = self.to_url()?;
        qrcodegen_image::draw_base64(&url).map_err(|url| TotpError::UrlTooLong { url })
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
    pub fn to_qr_png(&self) -> Result<alloc::vec::Vec<u8>, TotpError> {
        let url = self.to_url()?;
        qrcodegen_image::draw_png(&url).map_err(|url| TotpError::UrlTooLong { url })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "gen_secret")]
    fn default_values() {
        let totp = Totp::default();

        assert_eq!(totp.secret.len(), 20);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn generate_token() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert_eq!(&totp.generate(1000).to_string(), "659761");
    }

    #[test]
    #[cfg(feature = "std")]
    fn generate_token_current() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(totp.generate(time), totp.generate_current());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn generates_token_sha256() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA256)
            .with_step_duration(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert_eq!(&totp.generate(1000).to_string(), "076417");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn generates_token_sha512() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA512)
            .with_step_duration(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert_eq!(&totp.generate(1000).to_string(), "473536");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn checks_token() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_skew(0)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert!(totp.check("659761", 1000).is_some());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn checks_token_big_skew() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_skew(1001)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert!(totp.check("659761", 1000).is_some());
    }

    #[test]
    #[cfg(feature = "std")]
    fn checks_token_current() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_skew(0)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        let current = totp.generate_current().to_string();
        assert!(totp.check_current(&current).is_some());
        assert!(totp.check_current("bogus").is_none());
    }

    #[test]
    #[cfg(feature = "std")]
    fn check_ttl() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_skew(0)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();

        let ttl = totp.ttl();
        assert!((0..=totp.step).contains(&ttl));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn checks_token_with_skew() {
        let totp = Builder::new()
            .with_step_duration(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert!(
            totp.check("174269", 1000).is_some()
                && totp.check("659761", 1000).is_some()
                && totp.check("260393", 1000).is_some()
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn next_step() {
        let totp = Builder::new()
            .with_step_duration(30)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert!(totp.next_step(0) == 30);
        assert!(totp.next_step(29) == 30);
        assert!(totp.next_step(30) == 60);
    }

    #[test]
    #[cfg(feature = "std")]
    fn next_step_current() {
        let totp = Builder::new()
            .with_step_duration(30)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .build_noncompliant();
        assert!(totp.next_step_current() == totp.next_step(system_time()));
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use qrcodegen_image::qrcodegen;
        use sha2::{Digest, Sha512};

        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_step_duration(30)
            .with_skew(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .with_issuer("Github")
            .with_account_name("constantoine@github.com")
            .build_noncompliant();

        let url = totp.to_url().expect("could not generate url");
        let qr = qrcodegen::QrCode::encode_text(&url, qrcodegen::QrCodeEcc::Medium)
            .expect("could not generate qr");
        let data = qrcodegen_image::draw_canvas(qr).into_raw();

        // Create hash from image
        let hash_digest = Sha512::digest(data);
        let hash_hex: String = hash_digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hash_hex.as_str(),
            "fbb0804f1e4f4c689d22292c52b95f0783b01b4319973c0c50dd28af23dbbbe663dce4eb05a7959086d9092341cb9f103ec5a9af4a973867944e34c063145328"
        );
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_base64_ok() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_step_duration(1)
            .with_skew(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .with_issuer("Github")
            .with_account_name("constantoine@github.com")
            .build_noncompliant();

        let qr = totp.to_qr_base64();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_png_ok() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_step_duration(1)
            .with_skew(1)
            .with_secret("TestSecretSuperSecret".as_bytes())
            .with_issuer("Github")
            .with_account_name("constantoine@github.com")
            .build_noncompliant();

        let qr = totp.to_qr_png();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_url_too_long() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_step_duration(30)
            .with_skew(1)
            .with_secret(vec![0xAA; 2048])
            .with_issuer("Github")
            .with_account_name("constantoine@github.com")
            .build_noncompliant();

        assert!(totp.to_url().is_ok());

        let qr = totp.to_qr_base64();
        assert!(matches!(&qr, &Err(TotpError::UrlTooLong { .. })));
        let error_message = format!("{}", qr.unwrap_err());
        assert!(
            error_message.starts_with(
                "Could not generate a QR code: the generated URL is too long to encode"
            )
        );
    }

    /// Catch any egregious changes to the size of the [`Totp`] type to keep its
    /// stack size reasonably low.
    ///
    /// Sizes are pinned for 64-bit targets; 32-bit has narrower pointers.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn size_test() {
        if cfg!(feature = "otpauth") {
            assert_eq!(size_of::<Totp>(), 72);
        } else {
            assert_eq!(size_of::<Totp>(), 40);
        }
    }

    #[test]
    fn check_totp_display_implementation() {
        let totp = Builder::new().build_noncompliant();

        assert!(!totp.to_string().is_empty());
    }
}
