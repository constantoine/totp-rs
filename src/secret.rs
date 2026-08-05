//! Representation of a secret either a "raw" \[u8\] or "base 32" encoded String.
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
//! println!("code from raw secret:\t{}", totp.generate_current());
//! # }
//! ```
//!
//! - Create a TOTP from a base32 encoded secret
//! ```
//! # #[cfg(all(feature = "alloc", feature = "std"))] {
//! use totp_rs::{Algorithm, Builder, Secret};
//!
//! let secret = Secret::try_from_base32("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG").unwrap();
//! let totp = Builder::new()
//!         .with_secret(secret)
//!         .build()
//!         .unwrap();
//!
//! println!("code from base32:\t{}", totp.generate_current());
//! # }
//! ```
//! - Create a TOTP from a Generated Secret
//! ```
//! # #[cfg(all(feature = "gen_secret", feature = "std"))] {
//! use totp_rs::{Algorithm, Builder, Totp, Secret};
//!
//! let secret_b32 = Secret::default();
//! let totp_b32 = Builder::new()
//!         .with_secret(secret_b32)
//!         .build()
//!         .unwrap();
//!
//! println!("code from base32:\t{}", totp_b32.generate_current());
//! # }
//! ```
//! - Create a TOTP from a Generated Secret 2
//! ```
//! # #[cfg(all(feature = "gen_secret", feature = "std"))] {
//! use totp_rs::{Algorithm, Builder, Totp, Secret };
//!
//! let secret = Secret::generate();
//! let totp: Totp = Builder::new()
//!     .with_secret(secret)
//!     .build()
//!     .unwrap();
//!
//! println!("code from base32:\t{}", totp.generate_current());
//! # }
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Shared secret between client and server to validate token against/generate token from.
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
    /// the recommended size from [rfc-4226](https://www.rfc-editor.org/rfc/rfc4226#section-4).
    ///
    /// > The length of the shared secret MUST be at least 128 bits.
    /// > This document RECOMMENDs a shared secret length of 160 bits.
    ///
    /// <div class="warning">
    /// The generated secret is not guaranteed to be a valid UTF-8 sequence.
    /// Base-32 string representation is the canonical way of displaying it to a user if you ever need to.
    /// </div>
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
        Self::from(generate_random_bytes())
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
    /// Redacts the secret to avoid leaking it through the implicit paths that
    /// reach [`Debug`](core::fmt::Debug): derived `Debug`, logging, and
    /// `unwrap`/`assert` failures. Use [`Display`](core::fmt::Display),
    /// [`as_bytes`](Secret::as_bytes), or [`to_base32`](Secret::to_base32) to
    /// access the secret explicitly.
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
    /// assert_eq!(&format!("{sec:?}"), "REDACTED");
    /// # }
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "REDACTED")
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

#[cfg(feature = "serde")]
impl serde::Serialize for Secret {
    /// Human-readable formats (JSON, TOML, YAML, ...) receive the secret as an
    /// base32 string without padding, the same representation used in
    /// otpauth URLs and returned by [`Secret::to_base32`]. Binary formats
    /// receive the raw byte string.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&Base32Display(self.as_bytes()))
        } else {
            s.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Secret {
    /// Accepts the unpadded base32 string form (produced for
    /// human-readable formats), a byte string (produced for binary formats),
    /// and a sequence of integers (how self-describing formats without a
    /// native byte type, e.g. JSON, hand over serialized bytes).
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;

        impl<'de> serde::de::Visitor<'de> for SecretVisitor {
            type Value = Secret;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a secret as a base32 string or a sequence of bytes")
            }

            // Human-readable formats carry the base32 representation.
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Secret, E> {
                #[cfg(feature = "alloc")]
                {
                    Secret::try_from_base32(v).map_err(E::custom)
                }
                #[cfg(not(feature = "alloc"))]
                {
                    // 20 bytes encode to exactly 32 base32 characters.
                    if v.len() > 32 {
                        return Err(E::custom(
                            "a secret must be at most 20 bytes without the `alloc` feature",
                        ));
                    }
                    match decode_base32_stack(v) {
                        Some((buf, len)) => secret_from_bytes(&buf[..len]),
                        None => Err(E::custom("Could not decode base32 secret.")),
                    }
                }
            }

            // Binary formats with a native byte-string type. The default
            // `visit_byte_buf` forwards here, so the owned case is covered too.
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Secret, E> {
                secret_from_bytes(v)
            }

            // Self-describing formats without a byte type (e.g. JSON) hand the
            // bytes over as a sequence of integers.
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Secret, A::Error> {
                #[cfg(feature = "alloc")]
                {
                    let mut buf = Vec::with_capacity(seq.size_hint().unwrap_or(20));
                    while let Some(byte) = seq.next_element::<u8>()? {
                        buf.push(byte);
                    }
                    secret_from_bytes(&buf)
                }
                #[cfg(not(feature = "alloc"))]
                {
                    let mut buf = [0u8; 20];
                    let mut len = 0;
                    while let Some(byte) = seq.next_element::<u8>()? {
                        if len >= buf.len() {
                            return Err(serde::de::Error::custom(
                                "a secret must be at most 20 bytes without the `alloc` feature",
                            ));
                        }
                        buf[len] = byte;
                        len += 1;
                    }
                    secret_from_bytes(&buf[..len])
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SecretVisitor)
        } else {
            deserializer.deserialize_bytes(SecretVisitor)
        }
    }
}

/// Formats a byte slice as RFC 4648 base32 without padding, producing the same
/// output as [`Secret::to_base32`] without requiring `alloc`. Used to serialize
/// a [`Secret`] for human-readable formats.
#[cfg(feature = "serde")]
struct Base32Display<'a>(&'a [u8]);

#[cfg(feature = "serde")]
impl core::fmt::Display for Base32Display<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write;

        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        for chunk in self.0.chunks(5) {
            let mut group = [0u8; 5];
            group[..chunk.len()].copy_from_slice(chunk);
            let bits =
                u64::from_be_bytes([0, 0, 0, group[0], group[1], group[2], group[3], group[4]]);

            // ceil(chunk.len() * 8 / 5) characters carry data; the remainder
            // of the group would be padding.
            let chars = [2, 4, 5, 7, 8][chunk.len() - 1];
            for i in 0..chars {
                let index = (bits >> (35 - 5 * i)) & 0x1f;
                f.write_char(ALPHABET[index as usize] as char)?;
            }
        }

        Ok(())
    }
}

/// Decode UPPERCASE base32 string into a Stack secret.
/// Returns the buffer and the number of bytes decoded, or `None` on invalid or
/// too-long input.
///
/// Also compiled under `test` with `alloc` enabled so it can be checked against
/// the `base32` crate's decoder, which is unavailable in the builds that use
/// this function.
#[cfg(all(feature = "serde", any(not(feature = "alloc"), test)))]
fn decode_base32_stack(input: &str) -> Option<([u8; 20], usize)> {
    // 20 bytes encode to exactly 32 base32 characters.
    if input.len() > 32 {
        return None;
    }

    let mut out = [0u8; 20];
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut len = 0;
    for &c in input.as_bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[len] = (acc >> bits) as u8;
            len += 1;
        }
    }

    Some((out, len))
}

/// Build a [`Secret`] from raw bytes during deserialization, picking the storage
/// variant by length: a 20-byte secret is kept on the stack. With `alloc`, any
/// other length spills to the heap; without it, only an empty secret is allowed.
#[cfg(feature = "serde")]
fn secret_from_bytes<E: serde::de::Error>(bytes: &[u8]) -> Result<Secret, E> {
    if bytes.len() == 20 {
        // The length check guarantees this conversion succeeds.
        let array: [u8; 20] = bytes.try_into().unwrap();
        return Ok(Secret::new_stack(array));
    }

    #[cfg(feature = "alloc")]
    {
        Ok(Secret::new(bytes.into()))
    }
    #[cfg(not(feature = "alloc"))]
    {
        if bytes.is_empty() {
            Ok(Secret::empty())
        } else {
            Err(E::custom(
                "a secret must be 20 bytes (or empty) without the `alloc` feature",
            ))
        }
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

#[cfg(feature = "gen_secret")]
pub(crate) fn generate_random_bytes() -> [u8; 20] {
    fn generate_inner<const N: usize, T: rand::RngExt>(mut rng: T) -> [u8; N] {
        let mut secret = [0u8; N];
        rng.fill(&mut secret[..]);
        secret
    }

    // Attempt to use the thread-local CSPRNG from rand::rng() if `std` is enabled.
    // Otherwise, fallback to creating the same CSPRNG ourselves.
    // Cryptographically, these are equally secure, enabling `std` just allows
    // for potentially better performance, as seeding ChaCha12Rng has some initialisation cost.
    #[cfg(feature = "std")]
    return generate_inner(rand::rng());

    #[allow(
        unreachable_code,
        reason = "allowing an unreachable statement here ensures this codepath is valid even if no_std isn't properly tested."
    )]
    return generate_inner(rand::make_rng::<rand::rngs::ChaCha12Rng>());
}

#[cfg(feature = "alloc")]
const RFC4648_ALPHABET: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

/// Abstraction to allow for no_alloc secrets, or secrets on the heap.
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
        // `Display` exposes the secret as hex on explicit request.
        assert_eq!(&secret_raw.to_string(), BYTES_DISPLAY);
        assert_eq!(&secret_base32.to_string(), BYTES_DISPLAY);
        // `Debug` should not leak the secret as it is not always requested explicitly.
        assert_eq!(format!("{:?}", secret_base32), "REDACTED");
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
        assert!(matches!(Stack([0; 20]).clone(), Stack(..)));
    }
}

/// Serde tests live outside the `alloc`-gated module above so the no-`alloc`
/// code paths run under `--no-default-features --features serde`.
#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::{ByteStorage, Secret};
    use serde_test::{Configure, Token, assert_de_tokens, assert_de_tokens_error, assert_tokens};

    const STACK_20: [u8; 20] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];
    const STACK_20_BASE32: &str = "AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU";
    #[cfg(feature = "alloc")]
    const BYTES: [u8; 23] = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];

    /// A 20-byte secret serializes as a flat byte string in binary formats and
    /// an unpadded base32 string in human-readable formats, and round-trips
    /// back to the stack variant from both.
    #[test]
    fn serde_roundtrip_stack_20() {
        let secret = Secret::new_stack(STACK_20);
        assert!(matches!(secret.bytes, ByteStorage::Stack(_)));

        assert_tokens(&secret.clone().compact(), &[Token::Bytes(&STACK_20)]);
        assert_tokens(&secret.readable(), &[Token::Str(STACK_20_BASE32)]);
    }

    /// A non-20-byte secret serializes to the same two representations and,
    /// with `alloc`, round-trips back through the heap variant.
    #[test]
    #[cfg(feature = "alloc")]
    fn serde_roundtrip_heap_non_20() {
        let secret = Secret::from(BYTES); // 23 bytes
        assert!(matches!(secret.bytes, ByteStorage::Heap(_)));

        assert_tokens(&secret.clone().compact(), &[Token::Bytes(&BYTES)]);
        assert_tokens(
            &secret.readable(),
            &[Token::Str("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG")],
        );
    }

    /// Human-readable deserialization rejects input that is not unpadded
    /// uppercase base32, with and without `alloc`.
    #[test]
    fn serde_deserialize_rejects_invalid_base32() {
        for input in ["obwgc2lo", "OBWGC2LOFU======", "0189", "O!"] {
            assert_de_tokens_error::<serde_test::Readable<Secret>>(
                &[Token::Str(input)],
                "Could not decode base32 secret.",
            );
        }
    }

    /// Without `alloc`, a base32 string longer than a 20-byte secret reports
    /// the storage limit rather than a decode failure.
    #[test]
    #[cfg(not(feature = "alloc"))]
    fn serde_deserialize_rejects_over_32_chars_without_alloc() {
        assert_de_tokens_error::<serde_test::Readable<Secret>>(
            &[Token::Str("AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUA")], // 33 chars
            "a secret must be at most 20 bytes without the `alloc` feature",
        );
    }

    /// The allocation-free base32 encoder used for serialization must produce
    /// exactly the output of [`Secret::to_base32`] (the `base32` crate).
    #[test]
    #[cfg(feature = "alloc")]
    fn base32_display_matches_base32_crate() {
        use alloc::format;
        use alloc::vec::Vec;

        for len in 0..=41usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let secret = Secret::from(bytes.as_slice());
            assert_eq!(
                format!("{}", super::Base32Display(&bytes)),
                secret.to_base32(),
                "encoder mismatch at length {len}",
            );
        }
    }

    /// The allocation-free base32 decoder used for no-`alloc` deserialization
    /// must agree with the `base32` crate on canonical input, and reject the
    /// same malformed input.
    #[test]
    #[cfg(feature = "alloc")]
    fn decode_base32_stack_matches_base32_crate() {
        use super::{RFC4648_ALPHABET, decode_base32_stack};
        use alloc::vec::Vec;

        for len in 0..=20usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(13).wrapping_add(3))
                .collect();
            let encoded = Secret::from(bytes.as_slice()).to_base32();

            let (buf, decoded_len) = decode_base32_stack(&encoded).unwrap();
            assert_eq!(
                &buf[..decoded_len],
                &bytes[..],
                "decoder mismatch at length {len}"
            );
            assert_eq!(
                base32::decode(RFC4648_ALPHABET, &encoded).as_deref(),
                Some(&buf[..decoded_len]),
                "reference decoder disagrees at length {len}",
            );
        }

        // Longer than a 20-byte secret, lowercase, padding, and out-of-alphabet
        // characters are all rejected.
        for input in [
            "AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUA", // 33 chars
            "obwgc2lo",
            "OBWGC2LOFU======",
            "0189",
        ] {
            assert!(
                decode_base32_stack(input).is_none(),
                "decoder accepted malformed input {input:?}",
            );
        }
    }

    /// Self-describing formats without a byte type (e.g. JSON) hand the bytes
    /// over as a sequence of integers; deserialization must accept that too.
    #[test]
    fn serde_deserialize_from_integer_sequence() {
        // 20 bytes -> stack on the way back.
        assert_de_tokens(
            &Secret::new_stack(STACK_20).readable(),
            &seq_tokens(&STACK_20),
        );

        // Other lengths -> heap on the way back (`alloc` only).
        #[cfg(feature = "alloc")]
        assert_de_tokens(&Secret::from(BYTES).readable(), &seq_tokens(&BYTES));
    }

    /// Builds `Seq(...bytes...)` tokens. Tests always build with the std
    /// prelude, even when the `alloc` feature is off.
    fn seq_tokens(bytes: &'static [u8]) -> Vec<Token> {
        let mut tokens = vec![Token::Seq {
            len: Some(bytes.len()),
        }];
        tokens.extend(bytes.iter().map(|&b| Token::U8(b)));
        tokens.push(Token::SeqEnd);
        tokens
    }
}
