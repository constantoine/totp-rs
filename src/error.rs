#[cfg(feature = "otpauth")]
use url::ParseError;

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TotpError {
    // === Parameter validation errors ===
    /// Digits must be 6, 7, or 8.
    InvalidDigits { digits: usize },
    /// Step is zero.
    InvalidStepZero,
    /// Secret is shorter than 128 bits (16 bytes).
    SecretTooShort { bits: usize },

    // === URL parsing errors (otpauth feature) ===
    #[cfg(feature = "otpauth")]
    /// Algorithm is not recognized.
    InvalidAlgorithm { algorithm: String },
    #[cfg(feature = "otpauth")]
    /// Digits parameter is not a valid number.
    InvalidDigitsURL { digits: String },
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
    InvalidStepURL { step: String },

    // === Account/Issuer errors (otpauth feature) ===
    #[cfg(feature = "otpauth")]
    /// Account name contains invalid character ':'.
    InvalidAccountName { value: String },
    #[cfg(feature = "otpauth")]
    /// Account name URL decoding failed.
    AccountNameDecode { value: String },
    #[cfg(feature = "otpauth")]
    /// Issuer contains invalid character ':'.
    InvalidIssuer { value: String },
    #[cfg(feature = "otpauth")]
    /// Issuer URL decoding failed.
    IssuerDecode { value: String },
    #[cfg(feature = "otpauth")]
    /// Issuer in path differs from issuer in query parameter.
    IssuerMismatch { path: String, query: String },
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            #[cfg(feature = "otpauth")]
            TotpError::UrlParse(e) => write!(f, "Error parsing URL: {}", e),
            #[cfg(feature = "otpauth")]
            TotpError::InvalidAlgorithm { algorithm } => write!(
                f,
                "Algorithm must be SHA1, SHA256, or SHA512, not \"{}\"",
                algorithm
            ),
            #[cfg(feature = "otpauth")]
            TotpError::InvalidScheme { scheme } => {
                write!(f, "Scheme must be \"otpauth\", not \"{}\"", scheme)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidHost { host } => write!(f, "Host must be \"totp\", not \"{}\"", host),
            #[cfg(feature = "otpauth")]
            TotpError::InvalidStepURL { step } => {
                write!(f, "Could not parse step \"{}\" as a number", step)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidDigitsURL { digits } => {
                write!(f, "Could not parse digits \"{}\" as a number", digits)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidAccountName { value } => {
                write!(f, "Account name cannot contain ':', found in \"{}\"", value)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidSecret => {
                write!(f, "Could not parse secret as an unpadded base32 string")
            }
            #[cfg(feature = "otpauth")]
            TotpError::AccountNameDecode { value } => {
                write!(f, "Could not URL-decode account name \"{}\"", value)
            }
            #[cfg(feature = "otpauth")]
            TotpError::InvalidIssuer { value } => {
                write!(f, "Issuer cannot contain ':', found in \"{}\"", value)
            }
            #[cfg(feature = "otpauth")]
            TotpError::IssuerDecode { value } => {
                write!(f, "Could not URL-decode issuer \"{}\"", value)
            }
            #[cfg(feature = "otpauth")]
            TotpError::IssuerMismatch { path, query } => write!(
                f,
                "Issuer mismatch: path contains \"{}\" but query parameter contains \"{}\"",
                path, query
            ),
        }
    }
}

impl std::error::Error for TotpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
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
        let error = TotpError::InvalidAlgorithm {
            algorithm: "MD5".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Algorithm must be SHA1, SHA256, or SHA512, not \"MD5\""
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn invalid_digits_url() {
        let error = TotpError::InvalidDigitsURL {
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
    fn invalid_step_url() {
        let error = TotpError::InvalidStepURL {
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
    fn invalid_account_name() {
        let error = TotpError::InvalidAccountName {
            value: "user:name".to_string(),
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
            value: "bad%ZZencoding".to_string(),
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
            value: "Iss:uer".to_string(),
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
            value: "bad%ZZissuer".to_string(),
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
        use std::error::Error;

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
        use std::error::Error;

        let parse_error = url::ParseError::EmptyHost;
        let error = TotpError::UrlParse(parse_error);

        let source = error.source().expect("source should be Some");
        assert_eq!(source.to_string(), "empty host");
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn error_source_none_otpauth_variants() {
        use std::error::Error;

        let error = TotpError::InvalidAlgorithm {
            algorithm: "MD5".to_string(),
        };
        assert!(error.source().is_none());

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
