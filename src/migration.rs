//! Items and aliases to assist in migrating from 5.7.0 to 6.0.0
//!
//! Note this isn't enough to make the upgrade a minor patch, actual migration
//! from end users is almost certainly still required.
//! The goal of this module is to _try_ and catch compiler errors, and instead
//! provide more helpful warnings.

use crate::{Algorithm, Builder, Secret, SecretParseError, Totp, TotpError};

#[deprecated(since = "6.0.0", note = "renamed to `Totp` to be more idiomatic")]
pub type TOTP = Totp;

#[deprecated(since = "6.0.0", note = "replaced by `Builder`")]
pub type Rfc6238 = Builder;

#[deprecated(since = "6.0.0", note = "replaced by `TotpError`")]
pub type Rfc6238Error = TotpError;

#[deprecated(since = "6.0.0", note = "replaced by `TotpError`")]
pub type TotpUrlError = TotpError;

impl Totp {
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    #[deprecated(since = "6.0.0", note = "use `Builder::new` instead")]
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: alloc::vec::Vec<u8>,
        issuer: Option<alloc::string::String>,
        account_name: alloc::string::String,
    ) -> Result<Totp, TotpError> {
        let builder = Builder::new()
            .with_algorithm(algorithm)
            .with_digits(digits as _)
            .with_skew(skew as _)
            .with_step_duration(step as _)
            .with_secret(secret)
            .with_account_name(account_name);

        let builder = match issuer {
            Some(issuer) => builder.with_issuer(issuer),
            None => builder,
        };

        builder.build()
    }

    #[cfg(all(not(feature = "otpauth"), feature = "alloc"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "otpauth"), feature = "alloc"))))]
    #[deprecated(since = "6.0.0", note = "use `Builder::new` instead")]
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: alloc::vec::Vec<u8>,
    ) -> Result<Totp, TotpError> {
        let builder = Builder::new()
            .with_algorithm(algorithm)
            .with_digits(digits as _)
            .with_skew(skew as _)
            .with_step_duration(step as _)
            .with_secret(secret);

        builder.build()
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    #[deprecated(since = "6.0.0", note = "use `Builder::new` instead")]
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: alloc::vec::Vec<u8>,
        issuer: Option<alloc::string::String>,
        account_name: alloc::string::String,
    ) -> Totp {
        let builder = Builder::new()
            .with_algorithm(algorithm)
            .with_digits(digits as _)
            .with_skew(skew as _)
            .with_step_duration(step as _)
            .with_secret(secret)
            .with_account_name(account_name);

        let builder = match issuer {
            Some(issuer) => builder.with_issuer(issuer),
            None => builder,
        };

        builder.build_noncompliant()
    }

    #[cfg(all(not(feature = "otpauth"), feature = "alloc"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "otpauth"), feature = "alloc"))))]
    #[deprecated(since = "6.0.0", note = "use `Builder::new` instead")]
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: alloc::vec::Vec<u8>,
    ) -> Totp {
        let builder = Builder::new()
            .with_algorithm(algorithm)
            .with_digits(digits as _)
            .with_skew(skew as _)
            .with_step_duration(step as _)
            .with_secret(secret);

        builder.build_noncompliant()
    }

    #[deprecated(since = "6.0.0", note = "use `Builder::build` instead")]
    pub fn from_rfc6238(builder: Builder) -> Result<Totp, TotpError> {
        builder.build()
    }

    #[cfg(all(feature = "steam", feature = "otpauth"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "steam", feature = "otpauth"))))]
    #[deprecated(
        since = "6.0.0",
        note = "use `Builder::new_steam`, `Builder::with_secret`, and `Builder::with_account_name` instead"
    )]
    pub fn new_steam(secret: alloc::vec::Vec<u8>, account_name: alloc::string::String) -> Totp {
        Builder::new_steam()
            .with_secret(secret)
            .with_account_name(account_name)
            .build_noncompliant()
    }

    #[cfg(all(feature = "steam", not(feature = "otpauth"), feature = "alloc"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "steam", not(feature = "otpauth"), feature = "alloc")))
    )]
    #[deprecated(
        since = "6.0.0",
        note = "use `Builder::new_steam` and `Builder::with_secret` instead"
    )]
    pub fn new_steam(secret: alloc::vec::Vec<u8>) -> Totp {
        Builder::new_steam().with_secret(secret).build_noncompliant()
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[deprecated(
        since = "6.0.0",
        note = "use `Totp::secret` and `Secret::to_base32` instead"
    )]
    pub fn get_secret_base32(&self) -> alloc::string::String {
        self.secret().to_base32()
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    #[deprecated(since = "6.0.0", note = "use `Totp::to_url` instead")]
    pub fn get_url(&self) -> alloc::string::String {
        self.to_url().unwrap()
    }

    #[cfg(feature = "qr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
    #[deprecated(since = "6.0.0", note = "use `Totp::to_qr_base64` instead")]
    pub fn get_qr_base64(&self) -> Result<alloc::string::String, alloc::string::String> {
        self.to_qr_base64().map_err(|e| alloc::format!("{e}"))
    }

    #[cfg(feature = "qr")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
    #[deprecated(since = "6.0.0", note = "use `Totp::to_qr_png` instead")]
    pub fn get_qr_png(&self) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        self.to_qr_png().map_err(|e| alloc::format!("{e}"))
    }
}

impl Secret {
    #[cfg(feature = "gen_secret")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
    #[deprecated(since = "6.0.0", note = "use `Secret::generate` instead")]
    pub fn generate_secret() -> Self {
        Self::generate()
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[deprecated(since = "6.0.0", note = "use `Secret::as_bytes` instead")]
    pub fn to_bytes(&self) -> Result<alloc::vec::Vec<u8>, SecretParseError> {
        Ok(self.as_bytes().to_vec())
    }

    #[deprecated(since = "6.0.0", note = "use `Secret::as_bytes` instead")]
    pub fn to_raw(&self) -> Result<Self, SecretParseError> {
        Ok(self.clone())
    }

    #[deprecated(since = "6.0.0", note = "use `Secret::to_base32` instead")]
    pub fn to_encoded(&self) -> Self {
        self.clone()
    }
}

impl Builder {
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[deprecated(
        since = "6.0.0",
        note = "use `Builder::new` and `Builder::with_secret` instead"
    )]
    /// Only present to mirror [Rfc6238] during migration.
    /// See [Builder::with_secret] for more details on the values that would be used here.
    pub fn with_defaults(secret: alloc::vec::Vec<u8>) -> Result<Builder, TotpError> {
        Ok(Builder::new().with_secret(secret))
    }

    #[deprecated(since = "6.0.0", note = "use `Builder::with_digits` instead")]
    /// Only present to mirror [Rfc6238] during migration.
    /// See [Builder::with_digits] for more details on this value.
    pub fn digits(&mut self, value: usize) -> Result<(), TotpError> {
        *self = core::mem::take(self).with_digits(value as _);
        Ok(())
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    #[deprecated(since = "6.0.0", note = "use `Builder::with_issuer` instead")]
    /// Only present to mirror [Rfc6238] during migration.
    /// See [Builder::with_issuer] for more details on this value.
    pub fn issuer(&mut self, value: alloc::string::String) {
        *self = core::mem::take(self).with_issuer(value);
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    #[deprecated(since = "6.0.0", note = "use `Builder::with_account_name` instead")]
    /// Only present to mirror [Rfc6238] during migration.
    /// See [Builder::with_account_name] for more details on this value.
    pub fn account_name(&mut self, value: alloc::string::String) {
        *self = core::mem::take(self).with_account_name(value);
    }
}
