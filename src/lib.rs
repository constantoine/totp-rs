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
//! use std::time::SystemTime;
//! use totp_rs::{Algorithm, TOTP};
//!
//! let totp = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     "supersecret",
//!     Some("Github".to_string()),
//!     "constantoine@github.com".to_string(),
//! ).unwrap();
//! let token = totp.generate_current().unwrap();
//! println!("{}", token);
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
//!     "supersecret",
//!     Some("Github".to_string()),
//!     "constantoine@github.com".to_string(),
//! ).unwrap();
//! let url = totp.get_url();
//! println!("{}", url);
//! let code = totp.get_qr().unwrap();
//! println!("{}", code);
//! # }
//! ```

mod rfc;

pub use rfc::{Rfc6238, Rfc6238Error};

use constant_time_eq::constant_time_eq;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use core::fmt;

#[cfg(feature = "qr")]
use {base64, image::Luma, qrcodegen};

#[cfg(feature = "otpauth")]
use url::{Host, ParseError, Url};
#[cfg(feature = "otpauth")]
use urlencoding;

use hmac::Mac;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Algorithm enum holds the three standards algorithms for TOTP as per the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match *self {
            Algorithm::SHA1 => {
                f.write_str("SHA1")
            }
            Algorithm::SHA256 => {
                f.write_str("SHA256")
            }
            Algorithm::SHA512 => {
                f.write_str("SHA512")
            }
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
        match *self {
            Algorithm::SHA1 => Algorithm::hash(HmacSha1::new_from_slice(key).unwrap(), data),
            Algorithm::SHA256 => Algorithm::hash(HmacSha256::new_from_slice(key).unwrap(), data),
            Algorithm::SHA512 => Algorithm::hash(HmacSha512::new_from_slice(key).unwrap(), data),
        }
    }
}

fn system_time() -> Result<u64, SystemTimeError> {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    Ok(t)
}

#[derive(Debug, Eq, PartialEq)]
pub enum TotpUrlError {
    #[cfg(feature = "otpauth")]
    Url(ParseError),
    Scheme,
    Host,
    Secret,
    Algorithm,
    Digits,
    Step,
    Issuer,
    AccountName,
}

impl From<Rfc6238Error> for TotpUrlError {
    fn from(e: Rfc6238Error) -> Self {
        match e {
            Rfc6238Error::InvalidDigits => TotpUrlError::Digits,
            Rfc6238Error::SecretTooSmall => TotpUrlError::Secret,
        }
    }
}

/// TOTP holds informations as to how to generate an auth code and validate it. Its [secret](struct.TOTP.html#structfield.secret) field is sensitive data, treat it accordingly
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct TOTP<T = Vec<u8>> {
    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1
    pub algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits
    pub digits: usize,
    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid
    pub skew: u8,
    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    pub step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended
    pub secret: T,
    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    pub issuer: Option<String>,
    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    pub account_name: String
}

impl <T: AsRef<[u8]>> PartialEq for TOTP<T> {
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

impl<T: AsRef<[u8]>> TOTP<T> {
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
    ///
    /// # Description
    /// * `digits`: MUST be between 6 & 8
    ///
    /// # Errors
    ///
    /// Will return an error in case issuer or label contain the character ':'
    pub fn new(algorithm: Algorithm, digits: usize, skew: u8, step: u64, secret: T, issuer: Option<String>, account_name: String) -> Result<TOTP<T>, TotpUrlError> {
        crate::rfc::assert_digits(&digits)?;
        if issuer.is_some() && issuer.as_ref().unwrap().contains(':') {
            return Err(TotpUrlError::Issuer);
        }
        if account_name.contains(':') {
            return Err(TotpUrlError::AccountName);
        }
        Ok(TOTP {
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        })
    }

    /// Will create a new instance of TOTP from the given [Rfc6238](struct.Rfc6238.html) struct
    ///
    /// # Errors
    ///
    /// Will return an error in case issuer or label contain the character ':'
    pub fn from_rfc6238(rfc: Rfc6238<T>) -> Result<TOTP<T>, TotpUrlError> {
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
        let result = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!(
            "{1:00$}",
            self.digits,
            result % (10 as u32).pow(self.digits as u32)
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
    pub fn next_step_current(&self)-> Result<u64, SystemTimeError> {
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
        for i in 0..self.skew * 2 + 1 {
            let step_time = (basestep + (i as u64)) * (self.step as u64);

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
            base32::Alphabet::RFC4648 { padding: false },
            self.secret.as_ref(),
        )
    }

    /// Generate a TOTP from the standard otpauth URL
    #[cfg(feature = "otpauth")]
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<TOTP<Vec<u8>>, TotpUrlError> {
        let url = Url::parse(url.as_ref()).map_err(|err| TotpUrlError::Url(err))?;
        if url.scheme() != "otpauth" {
            return Err(TotpUrlError::Scheme);
        }
        if url.host() != Some(Host::Domain("totp")) {
            return Err(TotpUrlError::Host);
        }

        let mut algorithm = Algorithm::SHA1;
        let mut digits = 6;
        let mut step = 30;
        let mut secret = Vec::new();
        let mut issuer: Option<String> = None;
        let mut account_name: String;

        let path = url.path().trim_start_matches('/');
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(urlencoding::decode(parts.0.to_owned().as_str()).map_err(|_| TotpUrlError::Issuer)?.to_string());
            account_name = parts.1.trim_start_matches(':').to_owned();
        } else {
            account_name = path.to_owned();
        }

        account_name = urlencoding::decode(account_name.as_str()).map_err(|_| TotpUrlError::AccountName)?.to_string();

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "algorithm" => {
                    algorithm = match value.as_ref() {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => return Err(TotpUrlError::Algorithm),
                    }
                }
                "digits" => {
                    digits = value.parse::<usize>().map_err(|_| TotpUrlError::Digits)?;
                }
                "period" => {
                    step = value.parse::<u64>().map_err(|_| TotpUrlError::Step)?;
                }
                "secret" => {
                    secret =
                        base32::decode(base32::Alphabet::RFC4648 { padding: false }, value.as_ref())
                            .ok_or(TotpUrlError::Secret)?;
                }
                "issuer" => {
                    let param_issuer = value.parse::<String>().map_err(|_| TotpUrlError::Issuer)?;
                    if issuer.is_some() && param_issuer.as_str() != issuer.as_ref().unwrap() {
                        return Err(TotpUrlError::Issuer);
                    }
                    issuer = Some(param_issuer);
                }
                _ => {}
            }
        }

        if secret.is_empty() {
            return Err(TotpUrlError::Secret);
        }

        TOTP::new(algorithm, digits, 1, step, secret, issuer, account_name)
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    ///
    /// Label and issuer will be URL-encoded if needed be
    /// Secret will be base 32'd without padding, as per RFC.
    #[cfg(feature = "otpauth")]
    pub fn get_url(&self) -> String {
        let label: String;
        let account_name: String = urlencoding::encode(self.account_name.as_str()).to_string();
        if self.issuer.is_some() {
            let issuer: String = urlencoding::encode(self.issuer.as_ref().unwrap().as_str()).to_string();
            label = format!("{0}:{1}?issuer={0}&", issuer, account_name);
        } else {
            label = format!("{}?", account_name);
        }

        format!(
            "otpauth://totp/{}secret={}&digits={}&algorithm={}",
            label,
            self.get_secret_base32(),
            self.digits.to_string(),
            self.algorithm,
        )
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
    /// It will also return an error in case it can't encode the qr into a png. This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    #[cfg(feature = "qr")]
    pub fn get_qr(&self) -> Result<String, Box<dyn std::error::Error>> {
        use image::ImageEncoder;

        let url = self.get_url();
        let mut vec = Vec::new();
        let qr = qrcodegen::QrCode::encode_text(&url, qrcodegen::QrCodeEcc::Medium)?;
        let size = qr.size() as u32;

        // "+ 8 * 8" is here to add padding (the white border around the QRCode)
        // As some QRCode readers don't work without padding
        let image_size = size * 8 + 8 * 8;
        let mut canvas = image::GrayImage::new(image_size, image_size);

        // Draw the border
        for x in 0..image_size {
            for y in 0..image_size {
                if (y < 8*4 || y >= image_size - 8*4) || (x < 8*4 || x >= image_size - 8*4) {
                    canvas.put_pixel(x, y, Luma([255]));
                }
            }
        }

        // The QR inside the white border
        for x_qr in 0..size {
            for y_qr in 0..size {
                // The canvas is a grayscale image without alpha. Hence it's only one 8-bits byte longs
                // This clever trick to one-line the value was achieved with advanced mathematics
                // And deep understanding of Boolean algebra.
                let val = !qr.get_module(x_qr as i32, y_qr as i32) as u8 * 255;

                // Multiply coordinates by width of pixels
                // And take into account the 8*4 padding on top and left side
                let x_start = x_qr * 8 + 8*4;
                let y_start = y_qr * 8 + 8*4;

                // Draw a 8-pixels-wide square
                for x_img in x_start..x_start + 8 {
                    for y_img in y_start..y_start + 8 {
                        canvas.put_pixel(
                            x_img,
                            y_img,
                            Luma([val]),
                        );
                    }
                }
            }
        }

        // Encode the canvas into a PNG
        let encoder = image::codecs::png::PngEncoder::new(&mut vec);
        encoder.write_image(
            &image::ImageBuffer::from(canvas).into_raw(),
            image_size,
            image_size,
            image::ColorType::L8,
        )?;
        Ok(base64::encode(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wrong_issuer() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github:".to_string()), "constantoine@github.com".to_string());
        assert_eq!(totp.is_err(), true);
        assert_eq!(totp.unwrap_err(), TotpUrlError::Issuer);
    }

    #[test]
    fn new_wrong_account_name() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine:github.com".to_string());
        assert_eq!(totp.is_err(), true);
        assert_eq!(totp.unwrap_err(), TotpUrlError::AccountName);
    }

    #[test]
    fn new_wrong_account_name_no_issuer() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", None, "constantoine:github.com".to_string());
        assert_eq!(totp.is_err(), true);
        assert_eq!(totp.unwrap_err(), TotpUrlError::AccountName);
    }

    #[test]
    fn comparison_ok() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(reference, test);
    }

    #[test]
    fn comparison_different_algo() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_digits() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 8, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_skew() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_step() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_secret() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretL", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_ne!(reference, test);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha1_without_issuer() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", None, "constantoine@github.com".to_string()).unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA1");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha1() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA1");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha256() {
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA256");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_for_secret_matches_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA512");
    }

    #[test]
    fn returns_base32() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.get_secret_base32().as_str(), "KRSXG5CTMVRXEZLU");
    }

    #[test]
    fn generate_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "718996");
    }

    #[test]
    fn generate_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH).unwrap()
            .as_secs();
        assert_eq!(totp.generate(time).as_str(), totp.generate_current().unwrap());
    }

    #[test]
    fn generates_token_sha256() {
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "480200");
    }

    #[test]
    fn generates_token_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.generate(1000).as_str(), "850500");
    }

    #[test]
    fn checks_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert!(totp.check("718996", 1000));
        assert!(totp.check("712039", 2000));
        assert!(!totp.check("527544", 2000));
        assert!(!totp.check("714250", 2000));
    }

    #[test]
    fn checks_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert!(totp.check_current(&totp.generate_current().unwrap()).unwrap());
        assert!(!totp.check_current("bogus").unwrap());
    }

    #[test]
    fn checks_token_with_skew() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert!(
            totp.check("527544", 2000) && totp.check("712039", 2000) && totp.check("714250", 2000)
        );
    }

    #[test]
    fn next_step() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert!(totp.next_step(0) == 30);
        assert!(totp.next_step(29) == 30);
        assert!(totp.next_step(30) == 60);
    }

    #[test]
    fn next_step_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let t = system_time().unwrap();
        assert!(totp.next_step_current().unwrap() == totp.next_step(t));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_err() {
        assert!(TOTP::<Vec<u8>>::from_url("otpauth://hotp/123").is_err());
        assert!(TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test").is_err());
        assert!(TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256").is_err());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_default() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test?secret=ABC").unwrap();
        assert_eq!(totp.secret, base32::decode(base32::Alphabet::RFC4648 { padding: false }, "ABC").unwrap());
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test?secret=ABC&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(totp.secret, base32::decode(base32::Alphabet::RFC4648 { padding: false }, "ABC").unwrap());
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_to_url() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_issuer_special() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/Github%40:constantoine%40github.com?issuer=Github%40&secret=KRSXG5CTMVRXEZLU&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github@".to_string()), "constantoine@github.com".to_string()).unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query_issuer() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=ABC&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(totp.secret, base32::decode(base32::Alphabet::RFC4648 { padding: false }, "ABC").unwrap());
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_query_different_issuers() {
        let totp = TOTP::<Vec<u8>>::from_url("otpauth://totp/GitHub:test?issuer=Gitlab&secret=ABC&digits=8&period=60&algorithm=SHA256");
        assert_eq!(totp.is_err(), true);
        assert_eq!(totp.unwrap_err(), TotpUrlError::Issuer);
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use sha1::{Digest, Sha1};

        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret", Some("Github".to_string()), "constantoine@github.com".to_string()).unwrap();
        let qr = totp.get_qr().unwrap();

        // Create hash from image
        let hash_digest = Sha1::digest(qr.as_bytes());
        assert_eq!(
            format!("{:x}", hash_digest).as_str(),
            "b21a9d4bbb5bd0800bb6bff83a92a2e3314266a5"
        );
    }
}
