use crate::{Algorithm, Secret, Totp, TotpError};

/// Builder used to build a [Totp] with sane defaults.
/// Because it contains the sensitive data of the HMAC secret, treat it accordingly.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Builder {
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub(crate) algorithm: Algorithm,
    digits: u8,
    pub(crate) secret: Option<Secret>,
    skew: u16,
    step_duration: u64,

    #[cfg(feature = "otpauth")]
    account_name: alloc::boxed::Box<str>,
    #[cfg(feature = "otpauth")]
    issuer: Option<alloc::boxed::Box<str>>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// New [Builder] for [Totp].
    /// If `gen_secret` is enabled, [Self::build] and [Self::build_noncompliant] will generate a new, safe-to-use, secret. [Self::new] does not generate it eagerly.
    /// in case `gen_secret` is enabled, [Totp::default] will be equivalent to calling [Self::new] followed by [Self::build_noncompliant].
    pub fn new() -> Self {
        Builder {
            algorithm: Algorithm::SHA1,
            digits: 6,
            secret: None,
            skew: 1,
            step_duration: 30,
            #[cfg(feature = "otpauth")]
            account_name: "".into(),
            #[cfg(feature = "otpauth")]
            issuer: None,
        }
    }

    /// SHA-1 is the most widespread algorithm used, and for totp purposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted.
    /// It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512.
    ///
    /// <div class="warning">Not all clients support other algorithms than SHA-1, and some will silently accept them and use SHA-1 under the hood.</div>
    ///
    /// Unless called, the default value will be Algorithm::SHA1.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;

        self
    }

    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscillate between 6 and 8 digits.
    ///
    /// <div class="warning">Due to how the algorithm works, a value of 10 or more will panic upon trying to generate a code.</div>
    ///
    /// Unless called, the default value will be 6.
    pub fn with_digits(mut self, digits: u8) -> Self {
        self.digits = digits;

        self
    }

    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG.
    /// It should be at least 128 bits, but 160 are recommended.
    ///
    /// Unless called, and if feature `gen_secret` is enabled, a random 160bits secret from a strong source will be the default value.
    ///
    /// If feature `gen_secret` is not enabled, then not calling this method will result in [Self::build] to fail.
    pub fn with_secret(mut self, secret: impl Into<Secret>) -> Self {
        self.secret = Some(secret.into());

        self
    }

    /// Number of steps allowed as network delay. A value of 1 would mean a code valid for the step before or the step after current step would be accepted.
    /// The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1.
    /// Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid.
    ///
    /// Unless called, the default value will be 1.
    pub fn with_skew(mut self, skew: u16) -> Self {
        self.skew = skew;

        self
    }

    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds.
    ///
    /// Unless called, the default value will be 30.
    pub fn with_step_duration(mut self, step_duration: u64) -> Self {
        self.step_duration = step_duration;

        self
    }

    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    ///
    /// <div class="warning">The account name is not required by `build`: a `Totp` built without one
    /// can still generate and check tokens. It is only required by `Totp::to_url` (and therefore the
    /// QR helpers), which return `TotpError::AccountNameNotSet` if it was never set.</div>
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn with_account_name(mut self, account_name: impl Into<alloc::boxed::Box<str>>) -> Self {
        self.account_name = account_name.into();

        self
    }

    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    ///
    /// Unless called, an issuer will not be present.
    /// You should not have any need to unset it, but in case you do, you would need to call it with `None::<&str>`, as a bare `None` lacks type information.
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn with_issuer(mut self, issuer: Option<impl Into<alloc::boxed::Box<str>>>) -> Self {
        self.issuer = issuer.map(Into::into);

        self
    }

    /// Consume the builder into a [Totp]. See [its method's docs](struct.Builder.html#impl-Builder) for reference about each values.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "std")] {
    /// use totp_rs::{Algorithm, Builder, Totp};
    ///
    /// let secret: Vec<u8> = vec![0; 20]; // You want an actual 20bytes of randomness here.
    ///
    /// let totp: Totp = Builder::new().
    ///     with_algorithm(Algorithm::SHA256).
    ///     with_secret(secret).
    ///     build().
    ///     unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - If the `digits` or `secret` size are invalid.
    /// - If secret was not set using [Self::with_secret] and the feature `gen_secret` is not enabled.
    /// - If `step_duration` is 0.
    /// - If `issuer` or `account_name` contain the character ':' (`otpauth` feature).
    ///
    /// <div class="warning">With the `otpauth` feature, an unset or empty `account_name` is accepted
    /// here so that a `Totp` can still be built for generate/check only. It only causes
    /// `Totp::to_url` to fail later (with `TotpError::AccountNameNotSet`), not `build`.</div>
    #[cfg_attr(not(feature = "gen_secret"), allow(unused_mut))]
    pub fn build(mut self) -> Result<Totp, TotpError> {
        #[cfg(feature = "gen_secret")]
        if self.secret.is_none() {
            self.secret = Some(Secret::from(crate::secret::generate_random_bytes()));
        }

        let secret = self.secret.as_ref().ok_or(TotpError::SecretNotSet)?;

        match self.algorithm {
            Algorithm::SHA1 | Algorithm::SHA256 | Algorithm::SHA512 => {
                crate::rfc::assert_digits(self.digits)?;
            }
            #[cfg(feature = "steam")]
            Algorithm::Steam => {
                if self.digits != 5 {
                    return Err(TotpError::InvalidDigits {
                        digits: self.digits,
                    });
                }
            }
        }

        #[cfg(feature = "otpauth")]
        {
            crate::rfc::assert_issuer_valid(&self.issuer)?;

            // Allow an empty account name to ensure enabling `otpauth` does not break
            // existing code.
            if !self.account_name.is_empty() {
                crate::rfc::assert_account_name_valid(&self.account_name)?;
            }
        }

        crate::rfc::assert_secret_length(secret.as_ref())?;

        if self.step_duration == 0 {
            return Err(TotpError::InvalidStepZero);
        }

        Ok(self.build_noncompliant())
    }

    /// Consume the builder into a [Totp], without checking the values for RFC. See [its method's docs](struct.Builder.html#impl-Builder) for reference about each values.
    ///
    /// <div class="warning">Logical errors, such as a step_duration of 0, could cause other functions such as [Totp::generate] to panic.</div>
    /// <div class="warning">Due to how the algorithm works, a value of 10 or more will panic upon trying to generate a code.</div>
    /// <div class="warning">
    ///     Without the `gen_secret` feature, calling this method without
    ///     [Self::with_secret] produces a [Totp] with an empty secret:
    ///     it works, but generates the same predictable token sequence for every
    ///     such instance.
    /// </div>
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")] {
    /// use totp_rs::{Algorithm, Builder, Totp};
    ///
    /// let secret: Vec<u8> = Vec::new(); // You want an actual 20bytes of randomness here.
    ///
    /// let totp: Totp = Builder::new().
    ///     with_algorithm(Algorithm::SHA256).
    ///     with_secret(secret).
    ///     with_digits(9). // Not RFC-compliant.
    ///     build_noncompliant();
    /// # }
    /// ```
    pub fn build_noncompliant(mut self) -> Totp {
        #[cfg(feature = "gen_secret")]
        if self.secret.is_none() {
            self.secret = Some(Secret::from(crate::secret::generate_random_bytes()));
        }

        Totp {
            algorithm: self.algorithm,
            digits: self.digits,
            skew: self.skew,
            step: self.step_duration,
            secret: core::mem::take(&mut self.secret).unwrap_or_else(Secret::empty),

            #[cfg(feature = "otpauth")]
            issuer: core::mem::take(&mut self.issuer),
            #[cfg(feature = "otpauth")]
            account_name: core::mem::take(&mut self.account_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::TotpError;
    use crate::{Algorithm, Builder};

    #[cfg_attr(not(feature = "alloc"), expect(dead_code))]
    const GOOD_SECRET: &str = "01234567890123456789";
    #[cfg_attr(not(feature = "alloc"), expect(dead_code))]
    const SHORT_SECRET: &str = "tooshort";

    // === Defaults ===

    #[test]
    fn defaults_without_secret() {
        let builder = Builder::new();
        assert_eq!(builder.algorithm, Algorithm::SHA1);
        assert_eq!(builder.digits, 6);
        assert_eq!(builder.skew, 1);
        assert_eq!(builder.step_duration, 30);
    }

    #[test]
    fn defaults_without_secret_like_new() {
        let expected = Builder::new();
        let default = Builder::default();
        assert_eq!(expected.algorithm, default.algorithm);
        assert_eq!(expected.digits, default.digits);
        assert_eq!(expected.skew, default.skew);
        assert_eq!(expected.step_duration, default.step_duration);
    }

    #[test]
    #[cfg(all(feature = "gen_secret", feature = "alloc"))]
    fn build_generates_secret_with_gen_secret() {
        let totp = Builder::new().build().unwrap();
        assert_eq!(totp.secret().as_bytes().len(), 20);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn defaults_otpauth_fields() {
        let builder = Builder::new();
        assert_eq!(&*builder.account_name, "");
        assert!(builder.issuer.is_none());
    }

    // === Setters ===

    #[test]
    fn with_algorithm() {
        let builder = Builder::new().with_algorithm(Algorithm::SHA256);
        assert_eq!(builder.algorithm, Algorithm::SHA256);
    }

    #[test]
    fn with_digits() {
        let builder = Builder::new().with_digits(8);
        assert_eq!(builder.digits, 8);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn with_secret() {
        let builder = Builder::new().with_secret(GOOD_SECRET.as_bytes());
        let to_compare = GOOD_SECRET.as_bytes();

        assert_eq!(builder.secret.as_deref(), Some(to_compare));
    }

    #[test]
    fn with_skew() {
        let builder = Builder::new().with_skew(2);
        assert_eq!(builder.skew, 2);
    }

    #[test]
    fn with_step_duration() {
        let builder = Builder::new().with_step_duration(60);
        assert_eq!(builder.step_duration, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn with_account_name() {
        let builder = Builder::new().with_account_name("user@example.com");
        assert_eq!(&*builder.account_name, "user@example.com");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn with_issuer() {
        let builder = Builder::new().with_issuer(Some("Github"));
        assert_eq!(builder.issuer.as_deref().as_ref(), Some(&"Github"));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn without_issuer() {
        let builder = Builder::new().with_issuer(Some("Github"));
        assert_eq!(builder.issuer.as_deref().as_ref(), Some(&"Github"));
        let builder = builder.with_issuer(None::<&str>);
        assert_eq!(builder.issuer.as_ref(), None);
    }

    // === build() success ===

    #[test]
    #[cfg(feature = "alloc")]
    fn build_ok() {
        let totp = Builder::new().with_secret(GOOD_SECRET.as_bytes()).build();
        assert!(totp.is_ok());
        let totp = totp.unwrap();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
        assert_eq!(totp.secret().as_bytes(), GOOD_SECRET.as_bytes());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_with_all_fields() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA512)
            .with_digits(8)
            .with_skew(2)
            .with_step_duration(60)
            .with_secret(GOOD_SECRET.as_bytes())
            .build()
            .unwrap();
        assert_eq!(totp.algorithm, Algorithm::SHA512);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 2);
        assert_eq!(totp.step, 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_ok_otpauth() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_account_name("user@example.com")
            .with_issuer(Some("Github"))
            .build();
        assert!(result.is_ok());
        let totp = result.unwrap();
        assert_eq!(&*totp.account_name, "user@example.com");
        assert_eq!(totp.issuer.as_deref().as_ref(), Some(&"Github"));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_ok_without_issuer() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_account_name("user@example.com".to_string())
            .build();
        assert!(result.is_ok());
    }

    // === build() failures ===

    #[test]
    fn build_fails_secret_not_set() {
        let result = Builder::new().build();
        if cfg!(feature = "gen_secret") {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), TotpError::SecretNotSet);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_fails_step_zero() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_step_duration(0)
            .build();
        assert_eq!(result.unwrap_err(), TotpError::InvalidStepZero);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_fails_secret_too_short() {
        let builder = Builder::new().with_secret(SHORT_SECRET.as_bytes());
        let result = builder.build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TotpError::SecretTooShort { .. }
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_fails_digits_too_low() {
        let builder = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_digits(5);
        let result = builder.build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::InvalidDigits { digits: 5 });
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_fails_digits_too_high() {
        let builder = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_digits(9);
        let result = builder.build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::InvalidDigits { digits: 9 });
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_succeeds_empty_account_name() {
        let result = Builder::new().with_secret(GOOD_SECRET.as_bytes()).build();
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_fails_account_name_with_colon() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_account_name("user:name".to_string())
            .build();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TotpError::InvalidAccountName {
                account_name: "user:name".to_string()
            }
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_fails_issuer_with_colon() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_account_name("user@example.com")
            .with_issuer(Some("Iss:uer"))
            .build();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TotpError::InvalidIssuer {
                issuer: "Iss:uer".to_string()
            }
        );
    }

    // === build_noncompliant() ===

    #[test]
    #[cfg(feature = "alloc")]
    fn build_noncompliant_allows_invalid_digits() {
        let totp = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_digits(10)
            .build_noncompliant();
        assert_eq!(totp.digits, 10);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_noncompliant_allows_short_secret() {
        let totp = Builder::new()
            .with_secret(SHORT_SECRET.as_bytes())
            .build_noncompliant();
        assert_eq!(totp.secret().as_bytes(), SHORT_SECRET.as_bytes());
    }

    #[test]
    fn build_noncompliant_no_secret_uses_empty_default() {
        let totp = Builder::new().build_noncompliant();
        assert!(cfg!(feature = "gen_secret") ^ totp.secret.is_empty());
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn build_noncompliant_no_secret_uses_generated() {
        let totp = Builder::new().build_noncompliant();
        assert_eq!(totp.secret.len(), 20);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_noncompliant_allows_invalid_account_name() {
        let totp = Builder::new()
            .with_secret(GOOD_SECRET.as_bytes())
            .with_account_name("bad:name".to_string())
            .build_noncompliant();
        assert_eq!(&*totp.account_name, "bad:name");
    }

    // === Digits boundary values ===

    #[test]
    #[cfg(feature = "alloc")]
    fn build_accepts_digits() {
        for i in 6..=8 {
            let builder = Builder::new()
                .with_secret(GOOD_SECRET.as_bytes())
                .with_digits(i);
            assert!(builder.build().is_ok());
        }
    }

    // === Secret boundary ===

    #[test]
    #[cfg(feature = "alloc")]
    fn build_accepts_exactly_16_byte_secret() {
        let builder = Builder::new().with_secret(vec![0u8; 16]);
        assert!(builder.build().is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn build_rejects_15_byte_secret() {
        let result = Builder::new().with_secret(vec![0u8; 15]).build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::SecretTooShort { bits: 120 });
    }
}
