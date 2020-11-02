//! This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! Default features are kept as low-dependency as possible to ensure small binaries and short compilation time
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
//! let time = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH).unwrap()
//!     .as_secs();
//! let url = totp.get_url("user@example.com", "my-org.com");
//! println!("{}", url);
//! let token = totp.generate(time);
//! println!("{}", token);
//! ```
//!
//! ```rust
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
//! ```

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

#[cfg(feature = "qr")]
use {base64, image::Luma, qrcode::QrCode};

use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Algorithm enum holds the three standards algorithms for TOTP as per the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
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
        let ctr = (time / self.step).to_be_bytes();
        match self.algorithm {
            Algorithm::SHA1 => {
                let mut mac = HmacSha1::new_varkey(self.secret.as_ref()).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                let mut mac = HmacSha256::new_varkey(self.secret.as_ref()).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                let mut mac = HmacSha512::new_varkey(self.secret.as_ref()).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Will generate a token according to the provided timestamp in seconds
    pub fn generate(&self, time: u64) -> String {
        let result: &[u8] = &self.sign(time);
        let offset = (result[19] & 15) as usize;
        let mut rdr = Cursor::new(&result[offset..offset + 4]);
        let result = rdr.read_u32::<BigEndian>().unwrap() & 0x7fff_ffff;
        format!(
            "{1:00$}",
            self.digits,
            result % (10 as u32).pow(self.digits as u32)
        )
    }

    /// Will check if token is valid by current time, accounting [skew](struct.TOTP.html#structfield.skew)
    pub fn check(&self, token: &str, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..self.skew * 2 + 1 {
            let step_time = (basestep + (i as u64)) * (self.step as u64);
            if self.generate(step_time) == token {
                return true;
            }
        }
        false
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
        let algorithm = match self.algorithm {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
        };
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&digits={}&algorithm={}",
            label,
            self.get_secret_base32(),
            issuer,
            self.digits,
            algorithm,
        )
    }

    /// Will return a qrcode to automatically add a TOTP as a base64 string. Needs feature `qr` to be enabled!
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code
    ///
    /// It will also return an error in case it can't encode the qr into a png. This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    #[cfg(feature = "qr")]
    pub fn get_qr(&self, label: &str, issuer: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = self.get_url(label, issuer);
        let code = QrCode::new(&url)?;
        let mut vec = Vec::new();
        let size: u32 = ((code.width() + 8) * 8) as u32;
        let encoder = image::png::PngEncoder::new(&mut vec);
        encoder.encode(
            code.render::<Luma<u8>>().build().as_ref(),
            size,
            size,
            image::ColorType::L8,
        )?;
        Ok(base64::encode(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_secret_matches() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        let url = totp.get_url("test_url", "totp-rs");
        assert_eq!(url.as_str(), "otpauth://totp/test_url?secret=KRSXG5CTMVRXEZLU&issuer=totp-rs&digits=6&algorithm=SHA1");
    }

    #[test]
    fn returns_base32() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert_eq!(totp.get_secret_base32().as_str(), "KRSXG5CTMVRXEZLU");
    }

    #[test]
    fn generates_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "718996");
    }

    #[test]
    fn generates_token_sha256() {
        let totp = TOTP::new(Algorithm::SHA256, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "423657");
    }

    #[test]
    fn generates_token_sha512() {
        let totp = TOTP::new(Algorithm::SHA512, 6, 1, 1, "TestSecret");
        assert_eq!(totp.generate(1000).as_str(), "416767");
    }

    #[test]
    fn checks_token() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 1, "TestSecret");
        assert!(totp.check("718996", 1000));
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
            "3abc0127e7a2b1013fb25c97ef14422c1fe9e878"
        );
    }
}
