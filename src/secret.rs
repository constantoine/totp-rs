//! Representation of a secret either a "raw" \[u8\] or "base 32" encoded String
//!
//! # Examples
//!
//! - Create a TOTP from a "raw" secret
//! ```
//! # #[cfg(feature = "std")] {
//! use totp_rs::{Algorithm, Builder, Secret};
//!
//! let secret = [
//!     0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
//!     0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
//! ];
//! let totp = Builder::new()
//!         .with_secret(secret)
//!         .build()
//!         .unwrap();
//!
//! println!("code from raw secret:\t{}", totp.generate_current().unwrap());
//! # }
//! ```
//!
//! - Create a TOTP from a base32 encoded secret
//! ```
//! # #[cfg(feature = "alloc")] {
//! use totp_rs::{Algorithm, Builder, Secret};
//!
//! let secret = Secret::try_from_base32("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG").unwrap();
//! let totp = Builder::new()
//!         .with_secret(secret)
//!         .build()
//!         .unwrap();
//!
//! println!("code from base32:\t{}", totp.generate_current().unwrap());
//! # }
//! ```
//! - Create a TOTP from a Generated Secret
//! ```
//! # #[cfg(feature = "gen_secret")] {
//! use totp_rs::{Algorithm, Builder, Totp, Secret};
//!
//! let secret_b32 = Secret::default();
//! let totp_b32 = Builder::new()
//!         .with_secret(secret_b32)
//!         .build()
//!         .unwrap();
//!
//! println!("code from base32:\t{}", totp_b32.generate_current().unwrap());
//! # }
//! ```
//! - Create a TOTP from a Generated Secret 2
//! ```
//! # #[cfg(feature = "gen_secret")] {
//! use totp_rs::{Algorithm, Builder, Totp, Secret };
//!
//! let secret = Secret::generate();
//! let totp: Totp = Builder::new()
//!     .with_secret(secret)
//!     .build()
//!     .unwrap();
//!
//! println!("code from base32:\t{}", totp.generate_current().unwrap());
//! # }
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Shared secret between client and server to validate token against/generate token from.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Secret {
    bytes: ByteStorage,
}

impl Secret {
    /// Construct a new [`Secret`] from the provided owned slice of bytes.
    ///
    /// See also [`new_stack`](Self::new_stack).
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use totp_rs::Secret;
    /// # use alloc::boxed::Box;
    /// let bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let heap = Box::new(bytes);
    /// let sec = Secret::new(heap);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub const fn new(bytes: Box<[u8]>) -> Self {
        Self {
            bytes: ByteStorage::Heap(bytes),
        }
    }

    /// Constructs an empty secret.
    /// This is explicitly not a public method as there shouldn't be a reason
    /// for end users to create empty secrets.
    /// Used internally to allow [`Builder::build_noncompliant`](crate::Builder::build_noncompliant)
    /// to succeed even when `alloc` is disabled.
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: ByteStorage::Empty,
        }
    }

    /// Construct a new [`Secret`] from the provided array of bytes on the stack.
    /// As [rfc-4226](https://www.rfc-editor.org/rfc/rfc4226#section-4) recommends
    /// a 160 bit secret, the array _must_ have a size of 20 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::new_stack(bytes);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    pub const fn new_stack(bytes: [u8; 20]) -> Self {
        Self {
            bytes: ByteStorage::Stack(bytes),
        }
    }

    /// Get the bytes of this [`Secret`] as a slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// # let bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::new_stack(bytes);
    /// let sec_bytes = sec.as_bytes();
    /// assert_eq!(sec_bytes, &bytes);
    /// ```
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// Generate a CSPRNG binary value of 160 bits,
    /// the recomended size from [rfc-4226](https://www.rfc-editor.org/rfc/rfc4226#section-4).
    ///
    /// > The length of the shared secret MUST be at least 128 bits.
    /// > This document RECOMMENDs a shared secret length of 160 bits.
    ///
    /// ⚠️ The generated secret is not guaranteed to be a valid UTF-8 sequence.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let sec = Secret::generate();
    /// let bytes = sec.as_bytes();
    /// assert_eq!(bytes.len(), 20);
    /// ```
    #[cfg(feature = "gen_secret")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
    pub fn generate() -> Self {
        Self::from(generate_random_bytes().unwrap())
    }

    /// Parse a Base32 encoded string and use that as the bytes for a [`Secret`].
    ///
    /// See also [`to_base32`](Self::to_base32).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let base_32 = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    /// let bytes = [
    ///     0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74,
    ///     0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65, 0x63,
    ///     0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    /// ];
    ///
    /// let sec = Secret::try_from_base32(base_32).unwrap();
    ///
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn try_from_base32(value: impl AsRef<str>) -> Result<Self, SecretParseError> {
        match base32::decode(RFC4648_ALPHABET, value.as_ref()) {
            Some(buf) => Ok(buf.into()),
            None => Err(SecretParseError::ParseBase32),
        }
    }

    /// Format this secret as a Base32 encoded string.
    ///
    /// See also [`try_from_base32`](Self::try_from_base32).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let base_32 = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    /// let bytes = [
    ///     0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74,
    ///     0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65, 0x63,
    ///     0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    /// ];
    ///
    /// let sec = Secret::from(bytes);
    ///
    /// assert_eq!(&sec.to_base32(), base_32);
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_base32(&self) -> String {
        base32::encode(RFC4648_ALPHABET, self.bytes.as_bytes())
    }
}

impl Clone for Secret {
    /// Clones this [`Secret`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// # let bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// let sec_2 = sec.clone();
    /// assert_eq!(sec, sec_2);
    /// ```
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }

    /// Replaces this [`Secret`] with data from `source`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// # let a_bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// # let b_bytes: [u8; 20] = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    /// # assert_ne!(a_bytes, b_bytes);
    /// let mut a = Secret::from(a_bytes);
    /// let b = Secret::from(b_bytes);
    ///
    /// assert_ne!(a, b);
    ///
    /// a.clone_from(&b);
    ///
    /// assert_eq!(a, b);
    /// ```
    fn clone_from(&mut self, source: &Self) {
        self.bytes.clone_from(&source.bytes);
    }
}

impl PartialEq for Secret {
    /// Attempts to perform a constant time comparison between this and `other`.
    /// If both secrets have differing sizes, the comparison will _not_ be constant
    /// time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// # let a_bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// # let b_bytes: [u8; 20] = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    /// # assert_ne!(a_bytes, b_bytes);
    /// let a = Secret::from(a_bytes);
    /// let b = Secret::from(b_bytes);
    ///
    /// assert_ne!(a, b);
    ///
    /// let a = b.clone();
    ///
    /// assert_eq!(a, b);
    /// ```
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(self, other)
    }
}

impl Eq for Secret {}

#[cfg(feature = "gen_secret")]
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Secret {
    /// Creates a new [`Secret`] by generating 20 random bytes.
    ///
    /// See also [`generate`](Secret::generate).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let sec = Secret::default();
    /// let bytes = sec.as_bytes();
    /// assert_eq!(bytes.len(), 20);
    /// ```
    fn default() -> Self {
        Self::generate()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a> From<&'a [u8]> for Secret {
    /// Copies the provided byte-slice into a new heap allocation and uses it
    /// as a secret.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// let bytes = sec.as_bytes();
    /// assert_eq!(sec.as_bytes(), bytes);
    /// ```
    fn from(value: &'a [u8]) -> Self {
        Self::new(value.into())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<Box<[u8]>> for Secret {
    /// Constructs a new [`Secret`] by taking ownership of the provided [`Box`].
    ///
    /// See also [`new`](Secret::new).
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use totp_rs::Secret;
    /// # use alloc::boxed::Box;
    /// let bytes: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let heap: Box<[u8]> = Box::new(bytes);
    /// let sec = Secret::from(heap);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn from(value: Box<[u8]>) -> Self {
        Self::new(value)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<Vec<u8>> for Secret {
    /// Constructs a new [`Secret`] by taking ownership of the provided [`Vec`]
    /// and converting it into a [`Box`].
    ///
    /// See also [`new`](Secret::new) and [`into_boxed_slice`](Vec::into_boxed_slice).
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use totp_rs::Secret;
    /// # use alloc::vec;
    /// let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes.clone());
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn from(value: Vec<u8>) -> Self {
        Self::new(value.into())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const N: usize> From<[u8; N]> for Secret {
    /// Constructs a new [`Secret`] from the provided byte array.
    ///
    /// If the length of the array is _exactly_ 20 bytes, it will be stored on the stack.
    /// Otherwise, it will be copied into a [`Box`].
    ///
    /// See also [`new_stack`](Secret::new_stack) and [`new`](Secret::new).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn from(value: [u8; N]) -> Self {
        if N == 20 {
            // Shenanigans required as compiler isn't aware N == 20
            let value = (&value as &[u8]).try_into().unwrap();
            Self::new_stack(value)
        } else {
            Self::new(value.into())
        }
    }
}

// Negative cfg required to avoid specialization issues with From<[u8; N]> implementation
#[cfg(not(feature = "alloc"))]
impl From<[u8; 20]> for Secret {
    /// Constructs a new [`Secret`] from the provided byte array.
    ///
    /// Enabling the `alloc` feature will allow this trait to be implemented
    /// for any size of array.
    ///
    /// See also [`new_stack`](Secret::new_stack).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn from(value: [u8; 20]) -> Self {
        Self::new_stack(value)
    }
}

impl AsRef<[u8]> for Secret {
    /// Provides access to the inner bytes of this [`Secret`].
    ///
    /// See also [`as_bytes`](Secret::as_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::ops::Deref for Secret {
    type Target = [u8];

    /// Provides access to the inner bytes of this [`Secret`].
    ///
    /// See also [`as_bytes`](Secret::as_bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    /// let sec = Secret::from(bytes);
    /// assert_eq!(sec.as_bytes(), &bytes);
    /// ```
    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl core::fmt::Debug for Secret {
    /// Formats this [`Secret`] as a hexadecimal number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
    /// let sec = Secret::from(bytes);
    /// # #[cfg(feature = "alloc")] {
    /// # extern crate alloc;
    /// # use alloc::format;
    /// assert_eq!(&format!("{sec}"), "00000000000000000000000000000000deadbeef");
    /// # }
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, f)
    }
}

impl core::fmt::Display for Secret {
    /// Formats this [`Secret`] as a hexadecimal number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use totp_rs::Secret;
    /// let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
    /// let sec = Secret::from(bytes);
    /// # #[cfg(feature = "alloc")] {
    /// # extern crate alloc;
    /// # use alloc::format;
    /// assert_eq!(&format!("{sec}"), "00000000000000000000000000000000deadbeef");
    /// # }
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{:02x}", b)?;
        }

        Ok(())
    }
}

/// Different ways secret parsing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretParseError {
    /// Invalid base32 input.
    ParseBase32,
}

impl core::error::Error for SecretParseError {}

impl core::fmt::Display for SecretParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SecretParseError::ParseBase32 => write!(f, "Could not decode base32 secret."),
        }
    }
}

pub(crate) fn generate_random_bytes() -> Option<[u8; 20]> {
    #[cfg(feature = "gen_secret")]
    fn generate_inner<const N: usize, T: rand::RngExt>(mut rng: T) -> [u8; N] {
        let mut secret = [0u8; N];
        rng.fill(&mut secret[..]);
        secret
    }

    // Attempt to use the thread-local CSPRNG from rand::rng() if `std` is enabled.
    // Otherwise, fallback to creating the same CSPRNG ourselves.
    // Cryptographically, these are equally secure, enabling `std` just allows
    // for potentially better performance, as seeding ChaCha12Rng has some initialisation cost.
    #[cfg(all(feature = "gen_secret", feature = "std"))]
    return Some(generate_inner(rand::rng()));

    #[cfg(feature = "gen_secret")]
    #[allow(
        unreachable_code,
        reason = "allowing an unreachable statement here ensures this codepath is valid even if no_std isn't properly tested."
    )]
    return Some(generate_inner(rand::make_rng::<rand::rngs::ChaCha12Rng>()));

    #[allow(
        unreachable_code,
        reason = "allowing an unreachable statement here ensures this codepath is valid even if no_gen_secret isn't properly tested."
    )]
    None
}

#[cfg(feature = "alloc")]
const RFC4648_ALPHABET: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

/// Abstraction to allow for no_alloc secrets, or secrets on the heap.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
#[non_exhaustive]
enum ByteStorage {
    Empty,
    #[cfg(feature = "alloc")]
    Heap(Box<[u8]>),
    Stack([u8; 20]),
}

impl ByteStorage {
    const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            #[cfg(feature = "alloc")]
            Self::Heap(heap) => heap,
            Self::Stack(stack) => stack,
        }
    }
}

impl Clone for ByteStorage {
    fn clone(&self) -> Self {
        match self {
            Self::Empty => Self::Empty,
            #[cfg(feature = "alloc")]
            Self::Heap(heap) => Self::Heap(heap.clone()),
            Self::Stack(stack) => Self::Stack(*stack),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::{ByteStorage, Secret, SecretParseError};

    const BASE32: &str = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    const BYTES: [u8; 23] = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];
    const BYTES_DISPLAY: &str = "706c61696e2d737472696e672d7365637265742d313233";

    #[test]
    fn secret_display_and_debug() {
        let base32_str = String::from(BASE32);
        let secret_raw = Secret::from(BYTES);
        let secret_base32 = Secret::try_from_base32(base32_str).unwrap();
        println!("{}", secret_raw);
        assert_eq!(&secret_raw.to_string(), BYTES_DISPLAY);
        assert_eq!(&secret_base32.to_string(), BYTES_DISPLAY);
        assert_eq!(format!("{:?}", secret_base32), BYTES_DISPLAY);
    }

    #[test]
    fn secret_convert_base32_raw() {
        let secret_raw = Secret::from(BYTES);
        let secret_base32 = Secret::try_from_base32(BASE32);

        assert_eq!(&Ok(secret_raw), &secret_base32);
    }

    #[test]
    fn secret_as_bytes() {
        assert_eq!(Secret::from(BYTES).as_bytes(), BYTES);
        assert_eq!(
            Secret::try_from_base32(BASE32).as_deref(),
            Ok(BYTES.as_slice())
        );
    }

    #[test]
    fn secret_cloning_equality() {
        let a = Secret::from(BYTES);
        let b = Secret::clone(&a);
        assert_eq!(a, b);
    }

    #[test]
    fn secret_clone_from_equality() {
        let a = Secret::from(BYTES);
        let mut b = Secret::new_stack([0; 20]);
        assert_ne!(a, b);

        b.clone_from(&a);
        assert_eq!(a, b);
    }

    #[test]
    fn secret_from_box_equivalent_to_new() {
        let heap: Box<[u8]> = Box::new(BYTES);
        let a = Secret::new(heap.clone());
        let b = Secret::from(heap);
        assert_eq!(a, b);
    }

    #[test]
    fn secret_from_string() {
        let bytes = "TestSecretSuperSecret".as_bytes();
        let base_32 = "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ";

        let raw = Secret::from(bytes);
        let encoded = Secret::try_from_base32(base_32).unwrap();

        assert_eq!(&raw.to_base32(), base_32);
        assert_eq!(bytes, encoded.as_bytes());
    }

    #[test]
    fn secret_from_string_failure() {
        let base_32 = "1";

        let secret = Secret::try_from_base32(base_32);

        assert!(matches!(secret, Err(SecretParseError::ParseBase32)));
        let error = secret.unwrap_err();
        assert_eq!(&error.to_string(), "Could not decode base32 secret.");
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_secret() {
        let sec = Secret::generate();

        assert_eq!(sec.len(), 20);
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_gen_default() {
        let sec = Secret::default();

        assert_eq!(sec.len(), 20);
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn secret_empty() {
        let non_ascii = vec![240, 159, 146, 150];
        let sec = Secret::try_from_base32(core::str::from_utf8(&non_ascii).unwrap());
        assert!(sec.is_err());
    }

    #[test]
    fn bytestorage_cloning_consistency() {
        use ByteStorage::{Empty, Heap, Stack};
        assert!(matches!(Empty.clone(), Empty));
        assert!(matches!(Heap(Box::new([])).clone(), Heap(..)));
        assert!(matches!(Stack([0; _]).clone(), Stack(..)));
    }
}
