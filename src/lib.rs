//! This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! With additional feature "qr", you can use it to generate a base64 png qrcode.
//!
//! # Examples
//!
//! ```
//! use std::time::SystemTime;
//! use totp_rs::{Algorithm, TOTP};
//! 
//! let username = "example".to_string();
//! let totp = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     "supersecret".to_string().into_bytes(),
//! );
//! let time = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH).unwrap()
//!     .as_secs();
//! let url = totp.get_url(format!("account:{}", username), "my-org.com".to_string());
//! println!("{}", url);
//! let token = totp.generate(time);
//! println!("{}", token);
//! ```
//!
//! ```
//! use totp_rs::{Algorithm, TOTP};
//!
//! let username = "example".to_string();
//! let totp = TOTP::new(
//!     Algorithm::SHA1,
//!     6,
//!     1,
//!     30,
//!     "supersecret".to_string().into_bytes(),
//! );
//! let code = totp.get_qr(format!("account:{}", username), "my-org.com".to_string())?;
//! println!("{}", code);
//! ```

use serde::{Deserialize, Serialize};

use base32;

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
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// TOTP holds informations as to how to generate an auth code and validate it. Its [secret](struct.TOTP.html#structfield.secret) field is sensitive data, treat it accordingly
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TOTP {
    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1
    pub algorithm: Algorithm,
    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits
    pub digits: usize,
    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid
    pub skew: u8,
    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    pub step: u64,
    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended
    pub secret: Vec<u8>,
}

impl TOTP {
    /// Will create a new instance of TOTP with given parameters. See [the doc](struct.TOTP.html#fields) for reference as to how to choose those values
    pub fn new(algorithm: Algorithm, digits: usize, skew: u8, step: u64, secret: Vec<u8>) -> TOTP {
        TOTP {
            algorithm: algorithm,
            digits: digits,
            skew: skew,
            step: step,
            secret: secret,
        }
    }

    /// Will sign the given timestamp
    pub fn sign(&self, time: u64) -> Vec<u8> {
        let ctr = (time / self.step).to_be_bytes().to_vec();
        match self.algorithm {
            Algorithm::SHA1 => {
                let mut mac = HmacSha1::new_varkey(&self.secret).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                let mut mac = HmacSha256::new_varkey(&self.secret).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                let mut mac = HmacSha512::new_varkey(&self.secret).expect("no key");
                mac.update(&ctr);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Will generate a token according to the provided timestamp in seconds
    pub fn generate(&self, time: u64) -> String {
        let result: &[u8] = &self.sign(time);
        let offset = (result.as_ref()[19] & 15) as usize;
        let mut rdr = Cursor::new(result.as_ref()[offset..offset + 4].to_vec());
        let result = rdr.read_u32::<BigEndian>().unwrap() & 0x7fff_ffff;
        format!(
            "{1:00$}",
            self.digits,
            result % (10 as u32).pow(self.digits as u32)
        )
    }

    /// Will check if token is valid by current time, accounting [skew](struct.TOTP.html#structfield.skew)
    pub fn check(&self, token: String, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..self.skew * 2 + 1 {
            let step_time = (basestep + (i as u64)) * (self.step as u64);
            println!("{}", self.generate(step_time));
            if self.generate(step_time) == token {
                return true;
            }
        }
        false
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    pub fn get_url(&self, label: String, issuer: String) -> String {
        let algorithm: String;
        match self.algorithm {
            Algorithm::SHA1 => algorithm = "SHA1".to_string(),
            Algorithm::SHA256 => algorithm = "SHA256".to_string(),
            Algorithm::SHA512 => algorithm = "SHA512".to_string(),
        }
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&digits={}&algorithm={}",
            label,
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.secret),
            issuer,
            self.digits.to_string(),
            algorithm,
        )
    }

    /// Will return a qrcode to automatically add a TOTP as a base64 string. Needs feature "qr" to be set. It is by default
    ///
    /// # Errors
    ///
    /// This will return an error in case the URL gets too long to encode into a QR code
    ///
    /// It will also return an error in case it can't encode the qr into a png. This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly
    #[cfg(feature = "qr")]
    pub fn get_qr(
        &self,
        label: String,
        issuer: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = self.get_url(label, issuer);
        let code = QrCode::new(&url)?;
        let mut vec = Vec::new();
        let size: u32 = ((code.width() + 8) * 8) as u32;
        let encoder = image::png::PNGEncoder::new(&mut vec);
        encoder.encode(
            &code.render::<Luma<u8>>().build().to_vec(),
            size,
            size,
            image::ColorType::L8,
        )?;
        Ok(base64::encode(vec))
    }
}
