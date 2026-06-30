#[cfg(feature = "otpauth")]
use {crate::algorithm::UnsupportedAlgorithm, alloc::string::String, url::ParseError};

/// Errors produced when building or parsing a [`Totp`](crate::Totp).
///
/// Variant naming follows a fixed convention:
/// * `Invalid<Field>`: the field was read but its value is not acceptable.
/// * `<Field>Parse` / `<Field>Decode`: the raw input could not be interpreted
///   (numeric parse vs. percent-decoding, respectively).
/// * `<Field>Mismatch`: two inputs contradict each other.
/// * `<Field>NotSet`: a required input is absent.
/// * otherwise, a descriptive name (e.g. `SecretTooShort`, `UrlTooLong`).
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TotpError {
    // === Parameter validation errors ===
    /// Digits must be 6, 7, or 8.
    InvalidDigits { digits: u32 },
    /// Step is zero.
    InvalidStepZero,
    /// Secret is shorter than 128 bits (16 bytes).
    SecretTooShort { bits: usize },
    /// Secret was not set in builder.
    SecretNotSet,

    // === URL parsing errors (otpauth feature) ===
    #[cfg(feature = "otpauth")]
    /// Algorithm is not recognized.
    InvalidAlgorithm { cause: UnsupportedAlgorithm },
    #[cfg(feature = "otpauth")]
    /// Digits parameter is not a valid number.
    DigitsParse { digits: String },
    #[cfg(feature = "otpauth")]
    /// URL parsing failed.
    UrlParse(ParseError),
    #[cfg(feature = "otpauth")]
    /// Scheme must be "otpauth".
    InvalidScheme { scheme: String },
    #[cfg(feature = "otpauth")]
    /// Host must be "totp" (or "steam" with steam feature).
    InvalidHost { host: String },
    #[cfg(feature = "otpauth")]
    /// Secret parameter is not a valid non-padded base32 string.
    InvalidSecret,
    #[cfg(feature = "otpauth")]
    /// Step parameter is not a valid number.
    StepParse { step: String },

    // === Account/Issuer errors (otpauth feature) ===
    #[cfg(feature = "otpauth")]
    /// Account name is required to build an otpauth URL but was not set.
    AccountNameNotSet,
    #[cfg(feature = "otpauth")]
    /// Account name contains invalid character ':'.
    InvalidAccountName { account_name: String },
    #[cfg(feature = "otpauth")]
    /// Account name URL decoding failed.
    AccountNameDecode { account_name: String },
    #[cfg(feature = "otpauth")]
    /// Issuer contains invalid character ':'.
    InvalidIssuer { issuer: String },
    #[cfg(feature = "otpauth")]
    /// Issuer URL decoding failed.
    IssuerDecode { issuer: String },
    #[cfg(feature = "otpauth")]
    /// Issuer in path differs from issuer in query parameter.
    IssuerMismatch { path: String, query: String },

    // === QR Code Errors (qr feature) ===
    #[cfg(feature = "qr")]
    /// The generated URL is too long to encode as a QR code.
    UrlTooLong { url: String },
}

impl core::fmt::Display for TotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TotpError::SecretTooShort { bits } => write!(
                f,
                "The length of the shared secret MUST be at least 128 bits, got {} bits",
                bits
            ),
            TotpError::InvalidDigits { digits } => {
                write!(f, "Digits must be 6, 7, or 8, not {}", digits,)
            }
            TotpError::InvalidStepZero => write!(f, "Step cannot be 0."),
            TotpError::SecretNotSet => write!(
                f,
                "Secret was not set in builder. Consider using the `gen_secret` feature"
            ),
            #[cfg(feature = "otpauth")]
            TotpError::UrlParse(e) => write!(f, "Error parsing URL: {}", e),
            #[cfg(feature = "otpauth")]
            TotpError::InvalidAlgorithm { cause } => write!(f, "{}", cause),
            #[cfg(feature = "otpauth")]
            TotpError::InvalidScheme { scheme } => {
                write!(f, "Scheme must be \"otpauth\", not \"{}\"", scheme)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidHost { host } => write!(f, "Host must be \"totp\", not \"{}\"", host),
            #[cfg(feature = "otpauth")]
            TotpError::StepParse { step } => {
                write!(f, "Could not parse step \"{}\" as a number", step)
            }
            #[cfg(feature = "otpauth")]
            TotpError::DigitsParse { digits } => {
                write!(f, "Could not parse digits \"{}\" as a number", digits)
            }
            #[cfg(feature = "otpauth")]
            TotpError::AccountNameNotSet => {
                write!(f, "Account name is required to build an otpauth URL")
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidAccountName { account_name } => {
                write!(
                    f,
                    "Account name cannot contain ':', found in \"{}\"",
                    account_name
                )
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidSecret => {
                write!(f, "Could not parse secret as an unpadded base32 string")
            }
            #[cfg(feature = "otpauth")]
            TotpError::AccountNameDecode { account_name } => {
                write!(f, "Could not URL-decode account name \"{}\"", account_name)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidIssuer { issuer } => {
                write!(f, "Issuer cannot contain ':', found in \"{}\"", issuer)
            }
            #[cfg(feature = "otpauth")]
            TotpError::IssuerDecode { issuer } => {
                write!(f, "Could not URL-decode issuer \"{}\"", issuer)
            }
            #[cfg(feature = "otpauth")]
            TotpError::IssuerMismatch { path, query } => write!(
                f,
                "Issuer mismatch: path contains \"{}\" but query parameter contains \"{}\"",
                path, query
            ),
            #[cfg(feature = "qr")]
            TotpError::UrlTooLong { url } => write!(
                f,
                "Could not generate a QR code: the generated URL is too long to encode: {url}"
            ),
        }
    }
}

impl core::error::Error for TotpError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            #[cfg(feature = "otpauth")]
            TotpError::InvalidAlgorithm { cause } => Some(cause),
            #[cfg(feature = "otpauth")]
            TotpError::UrlParse(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::TotpError;

    // === Parameter validation errors ===

    #[test]
    fn invalid_digits() {
        let error = TotpError::InvalidDigits { digits: 5 };
        assert_eq!(error.to_string(), "Digits must be 6, 7, or 8, not 5");
    }

    #[test]
    fn invalid_digits_high() {
        let error = TotpError::InvalidDigits { digits: 10 };
        assert_eq!(error.to_string(), "Digits must be 6, 7, or 8, not 10");
    }

    #[test]
    fn invalid_step_zero() {
        let error = TotpError::InvalidStepZero;
        assert_eq!(error.to_string(), "Step cannot be 0.");
    }

    #[test]
    fn secret_too_short() {
        let error = TotpError::SecretTooShort { bits: 64 };
        assert_eq!(
            error.to_string(),
            "The length of the shared secret MUST be at least 128 bits, got 64 bits"
        );
    }

    // === URL parsing errors (otpauth feature) ===

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_algorithm() {
        let cause = crate::Algorithm::try_from("MD5".to_string()).unwrap_err();
        let error = TotpError::InvalidAlgorithm { cause };
        assert_eq!(error.to_string(), "Unsupported Algorithm: MD5");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn digits_parse() {
        let error = TotpError::DigitsParse {
            digits: "six".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Could not parse digits \"six\" as a number"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_parse() {
        let error = TotpError::UrlParse(url::ParseError::EmptyHost);
        assert_eq!(error.to_string(), "Error parsing URL: empty host");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_scheme() {
        let error = TotpError::InvalidScheme {
            scheme: "https".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Scheme must be \"otpauth\", not \"https\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_host() {
        let error = TotpError::InvalidHost {
            host: "hotp".to_string(),
        };
        assert_eq!(error.to_string(), "Host must be \"totp\", not \"hotp\"");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_secret() {
        let error = TotpError::InvalidSecret;
        assert_eq!(
            error.to_string(),
            "Could not parse secret as an unpadded base32 string"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn step_parse() {
        let error = TotpError::StepParse {
            step: "thirty".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Could not parse step \"thirty\" as a number"
        );
    }

    // === Account/Issuer errors (otpauth feature) ===

    #[test]
    #[cfg(feature = "otpauth")]
    fn account_name_not_set() {
        let error = TotpError::AccountNameNotSet;
        assert_eq!(
            error.to_string(),
            "Account name is required to build an otpauth URL"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_account_name() {
        let error = TotpError::InvalidAccountName {
            account_name: "user:name".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Account name cannot contain ':', found in \"user:name\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn account_name_decode() {
        let error = TotpError::AccountNameDecode {
            account_name: "bad%ZZencoding".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Could not URL-decode account name \"bad%ZZencoding\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_issuer() {
        let error = TotpError::InvalidIssuer {
            issuer: "Iss:uer".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Issuer cannot contain ':', found in \"Iss:uer\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn issuer_decode() {
        let error = TotpError::IssuerDecode {
            issuer: "bad%ZZissuer".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Could not URL-decode issuer \"bad%ZZissuer\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn issuer_mismatch() {
        let error = TotpError::IssuerMismatch {
            path: "Google".to_string(),
            query: "Github".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Issuer mismatch: path contains \"Google\" but query parameter contains \"Github\""
        );
    }

    // === Error trait implementation ===

    #[test]
    fn error_source_none() {
        use core::error::Error;

        let error = TotpError::SecretTooShort { bits: 64 };
        assert!(error.source().is_none());

        let error = TotpError::InvalidDigits { digits: 5 };
        assert!(error.source().is_none());

        let error = TotpError::InvalidStepZero;
        assert!(error.source().is_none());
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn error_source_url_parse() {
        use core::error::Error;

        let parse_error = url::ParseError::EmptyHost;
        let error = TotpError::UrlParse(parse_error);

        let source = error.source().expect("source should be Some");
        assert_eq!(source.to_string(), "empty host");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn error_source_invalid_algorithm() {
        use core::error::Error;

        let cause = crate::Algorithm::try_from("MD5".to_string()).unwrap_err();
        let error = TotpError::InvalidAlgorithm { cause };

        let source = error.source().expect("source should be Some");
        assert_eq!(source.to_string(), "Unsupported Algorithm: MD5");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn error_source_none_otpauth_variants() {
        use core::error::Error;

        let error = TotpError::InvalidScheme {
            scheme: "https".to_string(),
        };
        assert!(error.source().is_none());

        let error = TotpError::IssuerMismatch {
            path: "A".to_string(),
            query: "B".to_string(),
        };
        assert!(error.source().is_none());
    }
}
