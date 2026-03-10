use crate::error::TotpError;
use crate::{Algorithm, Totp};

/// Builder used to build a [Totp] with sane defaults.
/// Because it contains the sensitive data of the HMAC secret, treat it accordingly.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Builder {
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub(super) algorithm: Algorithm,
    pub(super) digits: u32,
    pub(super) secret: Option<Vec<u8>>,
    pub(super) skew: u32,
    pub(super) step_duration: u64,

    #[cfg(feature = "otpauth")]
    pub(super) account_name: String,
    #[cfg(feature = "otpauth")]
    pub(super) issuer: Option<String>,
}

impl Builder {
    /// New Builder.
    /// If `gen_secret` is enabled, [Self::new] will generate a new, safe-to-use, secret.
    /// in case `gen_secret` is enabled, [Totp::default] will be equivalent to calling [Self::new] followed by [Self::build] in which case
    /// After build, use [Totp::to_secret_binary] or [Totp::to_secret_base32] to retrieve the newly generated secret.
    pub fn new() -> Self {
        #[cfg(feature = "gen_secret")]
        let secret: Option<Vec<u8>> = {
            use rand::Rng;

            let mut rng = rand::rng();
            let mut secret: Vec<u8> = vec![0; 20];
            rng.fill(&mut secret[..]);

            Some(secret)
        };

        #[cfg(not(feature = "gen_secret"))]
        let secret = None;

        Builder {
            algorithm: Algorithm::SHA1,
            digits: 6,
            secret: secret,
            skew: 1,
            step_duration: 30,
            #[cfg(feature = "otpauth")]
            account_name: "".to_string(),
            #[cfg(feature = "otpauth")]
            issuer: None,
        }
    }

    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1.
    ///
    /// Unless called, the default value will be Algorithm::SHA1.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;

        self
    }

    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits.
    ///
    /// Unless called, the default value will be 6.
    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;

        self
    }

    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended.
    ///
    /// Unless called, and if feature `gen_secret` is enabled, a random 160bits secret from a strong source will be the default value.
    ///
    /// If feature `gen_secret` is not enabled, then not calling this method will result in [Self::build] to fail.
    pub fn with_secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = Some(secret);

        self
    }

    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid.
    ///
    /// Unless called, the default value will be 1.
    pub fn with_skew(mut self, skew: u32) -> Self {
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
    /// Not calling this method will result in [Self::build] to fail.
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn with_account_name(mut self, account_name: String) -> Self {
        self.account_name = account_name;

        self
    }

    /// The "Github" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your service/website.
    /// Not mandatory, but strongly recommended!
    ///
    /// Unless called, an issuer will not be present.
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn with_issuer(mut self, issuer: Option<String>) -> Self {
        self.issuer = issuer;

        self
    }

    /// Consume the builder into a [Totp]. See [its method's docs](struct.Builder.html#impl-Builder) for reference about each values.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(not(feature = "otpauth"))] {
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
    /// - If the `digit` or `secret` size are invalid.
    /// - If secret was not set using [Self::with_secret] and the feature `gen_secret` is not enabled.
    /// - If `issuer` is not set/is an empty string (`otpauth`` feature).
    /// - If `issuer` or `label` contain the character ':' (`otpauth`` feature).
    pub fn build(self) -> Result<Totp, TotpError> {
        let secret = self.secret.as_ref().ok_or(TotpError::SecretNotSet)?;

        #[cfg(feature = "steam")]
        {
            if self.algorithm != Algorithm::Steam {
                crate::rfc::assert_digits(self.digits)?;
            }
        }

        #[cfg(not(feature = "steam"))]
        crate::rfc::assert_digits(self.digits)?;
        crate::rfc::assert_secret_length(secret)?;

        #[cfg(feature = "otpauth")]
        {
            crate::rfc::assert_issuer_valid(&self.issuer)?;
            crate::rfc::assert_account_name_valid(&self.account_name)?;
        }

        Ok(self.build_noncompliant())
    }

    /// Consume the builder into a [Totp], without checking the values for RFC. See [its method's docs](struct.Builder.html#impl-Builder) for reference about each values.
    ///
    /// <div class="warning">Logical errors, such as a step_duration of 0, could cause other functions such as [Totp::generate] to panic.</div>
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Algorithm, Builder, Totp};
    ///
    /// let secret: Vec<u8> = Vec::new(); // You want an actual 20bytes of randomness here.
    ///
    /// let totp: Totp = Builder::new().
    ///     with_algorithm(Algorithm::SHA256).
    ///     with_secret(secret).
    ///     with_digits(10). // Not RFC-compliant.
    ///     build_noncompliant();
    /// ```
    pub fn build_noncompliant(mut self) -> Totp {
        Totp {
            algorithm: self.algorithm,
            digits: self.digits,
            skew: self.skew,
            step: self.step_duration,
            secret: std::mem::take(&mut self.secret).unwrap_or_default(),

            #[cfg(feature = "otpauth")]
            issuer: std::mem::take(&mut self.issuer),
            #[cfg(feature = "otpauth")]
            account_name: std::mem::take(&mut self.account_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::TotpError;
    use crate::{Algorithm, Builder};

    const GOOD_SECRET: &str = "01234567890123456789";

    const SHORT_SECRET: &str = "tooshort";

    // === Defaults ===

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn defaults_without_secret() {
        let builder = Builder::new();
        assert_eq!(builder.algorithm, Algorithm::SHA1);
        assert_eq!(builder.digits, 6);
        assert_eq!(builder.skew, 1);
        assert_eq!(builder.step_duration, 30);
    }

    #[test]
    #[cfg(not(feature = "gen_secret"))]
    fn defaults_secret_is_none_without_gen_secret() {
        let builder = Builder::new();
        assert!(builder.secret.is_none());
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn defaults_secret_is_generated_with_gen_secret() {
        let builder = Builder::new();
        assert!(builder.secret.as_ref().is_some());
        assert_eq!(builder.secret.as_ref().unwrap().len(), 20);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn defaults_otpauth_fields() {
        let builder = Builder::new();
        assert_eq!(builder.account_name, "");
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
    fn with_secret() {
        let builder = Builder::new().with_secret(GOOD_SECRET.into());
        assert_eq!(builder.secret.as_ref().unwrap(), GOOD_SECRET.as_bytes());
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
        let builder = Builder::new().with_account_name("user@example.com".to_string());
        assert_eq!(builder.account_name, "user@example.com");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn with_issuer() {
        let builder = Builder::new().with_issuer(Some("Github".to_string()));
        assert_eq!(builder.issuer, Some("Github".to_string()));
    }

    // === build() success ===

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_ok() {
        let totp = Builder::new().with_secret(GOOD_SECRET.into()).build();
        assert!(totp.is_ok());
        let totp = totp.unwrap();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
        assert_eq!(totp.secret, GOOD_SECRET.as_bytes());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_with_all_fields() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA512)
            .with_digits(8)
            .with_skew(2)
            .with_step_duration(60)
            .with_secret(GOOD_SECRET.into())
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
            .with_secret(GOOD_SECRET.into())
            .with_account_name("user@example.com".to_string())
            .with_issuer(Some("Github".to_string()))
            .build();
        assert!(result.is_ok());
        let totp = result.unwrap();
        assert_eq!(totp.account_name, "user@example.com");
        assert_eq!(totp.issuer, Some("Github".to_string()));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_ok_without_issuer() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_account_name("user@example.com".to_string())
            .build();
        assert!(result.is_ok());
    }

    // === build() failures ===

    #[test]
    #[cfg(not(feature = "gen_secret"))]
    fn build_fails_secret_not_set() {
        let result = Builder::new().build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::SecretNotSet);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_fails_secret_too_short() {
        let builder = Builder::new().with_secret(SHORT_SECRET.into());
        let result = builder.build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TotpError::SecretTooShort { .. }
        ));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_fails_digits_too_low() {
        let builder = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_digits(5);
        let result = builder.build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::InvalidDigits { digits: 5 });
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_fails_digits_too_high() {
        let builder = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_digits(9);
        let result = builder.build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::InvalidDigits { digits: 9 });
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_fails_empty_account_name() {
        let result = Builder::new().with_secret(GOOD_SECRET.into()).build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TotpError::InvalidAccountName { .. }
        ));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_fails_account_name_with_colon() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_account_name("user:name".to_string())
            .build();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TotpError::InvalidAccountName {
                value: "user:name".to_string()
            }
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn build_fails_issuer_with_colon() {
        let result = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_account_name("user@example.com".to_string())
            .with_issuer(Some("Iss:uer".to_string()))
            .build();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TotpError::InvalidIssuer {
                value: "Iss:uer".to_string()
            }
        );
    }

    // === build_noncompliant() ===

    #[test]
    fn build_noncompliant_allows_invalid_digits() {
        let totp = Builder::new()
            .with_secret(GOOD_SECRET.into())
            .with_digits(10)
            .build_noncompliant();
        assert_eq!(totp.digits, 10);
    }

    #[test]
    fn build_noncompliant_allows_short_secret() {
        let totp = Builder::new()
            .with_secret(SHORT_SECRET.into())
            .build_noncompliant();
        assert_eq!(totp.secret, SHORT_SECRET.as_bytes());
    }

    #[test]
    #[cfg(not(feature = "gen_secret"))]
    fn build_noncompliant_no_secret_uses_empty_default() {
        let totp = Builder::new().build_noncompliant();
        assert!(totp.secret.is_empty());
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
            .with_secret(GOOD_SECRET.into())
            .with_account_name("bad:name".to_string())
            .build_noncompliant();
        assert_eq!(totp.account_name, "bad:name");
    }

    // === Digits boundary values ===

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_accepts_digits() {
        for i in 6..=8 {
            let builder = Builder::new()
                .with_secret(GOOD_SECRET.into())
                .with_digits(i);
            assert!(builder.build().is_ok());
        }
    }

    // === Secret boundary ===

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_accepts_exactly_16_byte_secret() {
        let builder = Builder::new().with_secret(vec![0u8; 16]);
        assert!(builder.build().is_ok());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn build_rejects_15_byte_secret() {
        let result = Builder::new().with_secret(vec![0u8; 15]).build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TotpError::SecretTooShort { bits: 120 });
    }
}
