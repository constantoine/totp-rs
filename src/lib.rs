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
//! );
//! let url = totp.get_url("user@example.com", "my-org.com");
//! println!("{}", url);
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
//! );
//! let code = totp.get_qr("user@example.com", "my-org.com").unwrap();
//! println!("{}", code);
//! # }
//! ```

use constant_time_eq::constant_time_eq;

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use core::fmt;

#[cfg(feature = "qr")]
use {base64, image::Luma, qrcodegen};

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
        match *self {
            Algorithm::SHA1 => {
                return f.write_str("SHA1");
            }
            Algorithm::SHA256 => {
                return f.write_str("SHA256");
            }
            Algorithm::SHA512 => {
                return f.write_str("SHA512");
            }
        }
    }
}

impl Algorithm {
    fn hash<D>(mut digest: D, data: &[u8]) -> Vec<u8>
    where
        D: hmac::Mac,
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
}

impl <T: AsRef<[u8]>> PartialEq for TOTP<T> {
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
    pub fn new(algorithm: Algorithm, digits: usize, skew: u8, step: u64, secret: T) -> TOTP<T> {
        TOTP {
            algorithm,
            digits,
            skew,
            step,
            secret,
        }
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

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    pub fn get_url(&self, label: &str, issuer: &str) -> String {
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&digits={}&algorithm={}",
            label.to_string(),
            self.get_secret_base32(),
            issuer.to_string(),
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
    pub fn get_qr(&self, label: &str, issuer: &str) -> Result<String, Box<dyn std::error::Error>> {
        use image::ImageEncoder;

        let url = self.get_url(label, issuer);
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
    fn comparison_ok() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert_eq!(reference, test);
    }

    #[test]
    fn comparison_different_algo() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret");
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_digits() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA1, 8, 1, 1, "TestSecret");
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_skew() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret");
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_step() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 30, "TestSecret");
        assert_ne!(reference, test);
    }

    #[test]
    fn comparison_different_secret() {
        let reference = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let test = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecretL");
        assert_ne!(reference, test);
    }

    #[test]
    fn url_for_secret_matches_sha1() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let url = totp.get_url("test_url", "totp-rs");
        assert_eq!(url.as_str(), "otpauth://totp/test_url?secret=KRSXG5CTMVRXEZLU&issuer=totp-rs&digits=6&algorithm=SHA1");
    }

    #[test]
    fn url_for_secret_matches_sha256() {
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret");
        let url = totp.get_url("test_url", "totp-rs");
        assert_eq!(url.as_str(), "otpauth://totp/test_url?secret=KRSXG5CTMVRXEZLU&issuer=totp-rs&digits=6&algorithm=SHA256");
    }

    #[test]
    fn url_for_secret_matches_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecret");
        let url = totp.get_url("test_url", "totp-rs");
        assert_eq!(url.as_str(), "otpauth://totp/test_url?secret=KRSXG5CTMVRXEZLU&issuer=totp-rs&digits=6&algorithm=SHA512");
    }

    #[test]
    fn returns_base32() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert_eq!(totp.get_secret_base32().as_str(), "KRSXG5CTMVRXEZLU");
    }

    #[test]
    fn generate_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "718996");
    }

    #[test]
    fn generate_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH).unwrap()
            .as_secs();
        assert_eq!(totp.generate(time).as_str(), totp.generate_current().unwrap());
    }

    #[test]
    fn generates_token_sha256() {
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "480200");
    }

    #[test]
    fn generates_token_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "850500");
    }

    #[test]
    fn checks_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret");
        assert!(totp.check("718996", 1000));
        assert!(totp.check("712039", 2000));
        assert!(!totp.check("527544", 2000));
        assert!(!totp.check("714250", 2000));
    }

    #[test]
    fn checks_token_current() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 0, 1, "TestSecret");
        assert!(totp.check_current(&totp.generate_current().unwrap()).unwrap());
        assert!(!totp.check_current("bogus").unwrap());
    }

    #[test]
    fn checks_token_with_skew() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert!(
            totp.check("527544", 2000) && totp.check("712039", 2000) && totp.check("714250", 2000)
        );
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use sha1::{Digest, Sha1};

        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let qr = totp.get_qr("test_url", "totp-rs").unwrap();

        // Create hash from image
        let hash_digest = Sha1::digest(qr.as_bytes());
        assert_eq!(
            format!("{:x}", hash_digest).as_str(),
            "f671a5a553227a9565c6132024808123f2c9e5e3"
        );
    }
}
