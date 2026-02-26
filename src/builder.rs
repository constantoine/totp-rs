use crate::error::TotpError;
use crate::{Algorithm, Totp};

/// Builder used to build a [Totp] with sane defaults.
/// Because it contains the sensitive data of the HMAC secret, treat it accordingly.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Builder {
    algorithm: Algorithm,
    digits: u32,
    secret: Option<Vec<u8>>,
    skew: u32,
    step_duration: u64,

    #[cfg(feature = "otpauth")]
    account_name: String,
    #[cfg(feature = "otpauth")]
    issuer: Option<String>,
}

impl Builder {
    /// New builder.
    /// If `gen_secret` is enabled, [Self::new] will generate a new, safe-to-use, secret.
    pub fn new() -> Builder {
        #[cfg(feature = "gen_secret")]
        let secret = {
            use rand::Rng;

            let mut rng = rand::rng();
            let mut secret: [u8; 20] = Default::default();
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
            account_name: None,
            #[cfg(feature = "otpauth")]
            issuer: "".to_string()
        }
    }

    /// SHA-1 is the most widespread algorithm used, and for totp pursposes, SHA-1 hash collisions are [not a problem](https://tools.ietf.org/html/rfc4226#appendix-B.2) as HMAC-SHA-1 is not impacted. It's also the main one cited in [rfc-6238](https://tools.ietf.org/html/rfc6238#section-3) even though the [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A) permits the use of SHA-1, SHA-256 and SHA-512. Not all clients support other algorithms then SHA-1.
    ///
    /// Unless called, the default value will be Algorithm::SHA1.
    pub fn with_algorithm(&mut self, algorithm: Algorithm) -> &mut Self {
        self.algorithm = algorithm;

        self
    }

    /// The number of digits composing the auth code. Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this can oscilate between 6 and 8 digits.
    ///
    /// Unless called, the default value will be 6.
    pub fn with_digits(&mut self, digits: u32) -> &mut Self {
        self.digits = digits;

        self
    }

    /// As per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-4) the secret should come from a strong source, most likely a CSPRNG. It should be at least 128 bits, but 160 are recommended.
    ///
    /// Unless called, and if feature `gen_secret` is enabled, a random 160bits secret from a strong source will be the default value.
    ///
    /// If feature `gen_secret` is not enabled, then not calling this method will result in [Self::build] to fail.
    pub fn with_secret(&mut self, secret: Vec<u8>) -> &mut Self {
        self.secret = Some(secret);

        self
    }

    /// Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1. Anything more is sketchy, and anyone recommending more is, by definition, ugly and stupid.
    ///
    /// Unless called, the default value will be 1.
    pub fn with_skew(&mut self, skew: u32) -> &mut Self {
        self.skew = skew;

        self
    }

    /// Duration in seconds of a step. The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds.
    ///
    /// Unless called, the default value will be 30.
    pub fn with_step_duration(&mut self, step_duration: u64) -> &mut Self {
        self.step_duration = step_duration;

        self
    }

    /// The "constantoine@github.com" part of "Github:constantoine@github.com". Must not contain a colon `:`
    /// For example, the name of your user's account.
    ///
    /// Not calling this method will result in [Self::build] to fail.
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub fn with_account_name(&mut self, account_name: String) -> &mut Self {
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
    pub fn with_issuer(&mut self, issuer: Option<String>) -> &mut Self {
        self.issuer = issuer;

        self
    }

    /// Consume the builder into a [Totp]. See [its method's docs](struct.Builder.html#impl-Builder) for reference about each values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use totp_rs::{Algorithm, Builder, Totp};
    /// use rand::Rng;
    ///
    /// let mut rng = rand::rng();
    /// let mut secret: [u8; 20] = Default::default();
    /// rng.fill(&mut secret[..]);
    ///
    /// let totp: Totp = Builder::new().
    ///     with_algorithm(Algorithm::SHA256).
    ///     with_secret(secret).
    ///     build().
    ///     unwrap()
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

        crate::rfc::assert_digits(self.digits)?;
        crate::rfc::assert_secret_length(secret)?;

        #[cfg(feature = "otpauth")]
        {
            if self.issuer.is_some() && self.issuer.as_ref().unwrap().contains(':') {
                return Err(TotpError::InvalidIssuer {
                    value: issuer.as_ref().unwrap().to_string(),
                });
            }

            if self.account_name.as_ref().is_empty || self.account_name.as_ref().contains(':') {
                return Err(TotpError::InvalidAccountName {
                    value: account_name,
                });
            }
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
    /// use rand::Rng;
    ///
    /// let mut rng = rand::rng();
    /// let mut secret: [u8; 20] = Default::default();
    /// rng.fill(&mut secret[..]);
    ///
    /// let totp: Totp = Builder::new().
    ///     with_algorithm(Algorithm::SHA256).
    ///     with_secret(secret).
    ///     with_digits(10). // Not RFC-compliant.
    ///     build_noncompliant()
    /// ```
    pub fn build_noncompliant(self) -> Totp {
        Totp {
            algorithm: self.algorithm,
            digits: self.digits,
            skew: self.skew,
            step: self.step_duration,
            secret: self.secret.unwrap_or_default(),

            #[cfg(feature = "otpauth")]
            issuer: self.issuer,
            #[cfg(feature = "otpauth")]
            account_name: self.account_name,
        }
    }
}
