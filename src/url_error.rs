#[cfg(feature = "otpauth")]
use url::ParseError;

use crate::Rfc6238Error;

#[derive(Debug, Eq, PartialEq)]
pub enum TotpUrlError {
    #[cfg(feature = "otpauth")]
    Url(ParseError),
    Scheme(String),
    Host(String),
    Secret(String),
    SecretSize(usize),
    Algorithm(String),
    Digits(String),
    DigitsNumber(usize),
    Step(String),
    Issuer(String),
    IssuerDecoding(String),
    IssuerMistmatch(String, String),
    AccountName(String),
    AccountNameDecoding(String),
}

impl std::error::Error for TotpUrlError {}

impl std::fmt::Display for TotpUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpUrlError::AccountName(name) => write!(
                f,
                "Account Name can't contain a colon. \"{}\" contains a colon",
                name
            ),
            TotpUrlError::AccountNameDecoding(name) => write!(
                f,
                "Couldn't URL decode \"{}\"",
                name
            ),
            TotpUrlError::Algorithm(algo) => write!(
                f,
                "Algorithm can only be SHA1, SHA256 or SHA512, not \"{}\"",
                algo
            ),
            TotpUrlError::Digits(digits) => write!(
                f,
                "Could not parse \"{}\" as a number.",
                digits,
            ),
            TotpUrlError::DigitsNumber(digits) => write!(
                f,
                "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code. {} digits is not allowed",
                digits,
            ),
            TotpUrlError::Host(host) => write!(
                f,
                "Host should be totp, not \"{}\"",
                host
            ),
            TotpUrlError::Issuer(issuer) => write!(
                f,
                "Issuer can't contain a colon. \"{}\" contains a colon",
                issuer
            ),
            TotpUrlError::IssuerDecoding(issuer) => write!(
                f,
                "Couldn't URL decode \"{}\"",
                issuer
            ),
            TotpUrlError::IssuerMistmatch(path_issuer, issuer) => write!(
                f,
                "An issuer \"{}\" could be retrieved from the path, but a different issuer \"{}\" was found in the issuer URL parameter",
                path_issuer,
                issuer,
            ),
            TotpUrlError::Scheme(scheme) => write!(
                f,
                "Scheme should be otpauth, not \"{}\"",
                scheme
            ),
            TotpUrlError::Secret(secret) => write!(
                f,
                "Secret \"{}\" is not a valid non-padded base32 string",
                secret,
            ),
            TotpUrlError::SecretSize(bits) => write!(
                f,
                "The length of the shared secret MUST be at least 128 bits. {} bits is not enough",
                bits,
            ),
            TotpUrlError::Step(step) => write!(
                f,
                "Could not parse \"{}\" as a number.",
                step,
            ),
            #[cfg(feature = "otpauth")]
            TotpUrlError::Url(e) => write!(
                f,
                "Error parsing URL: {}",
                e
            )
        }
    }
}

impl From<Rfc6238Error> for TotpUrlError {
    fn from(e: Rfc6238Error) -> Self {
        match e {
            Rfc6238Error::InvalidDigits(digits) => TotpUrlError::DigitsNumber(digits),
            Rfc6238Error::SecretTooSmall(bits) => TotpUrlError::SecretSize(bits),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::TotpUrlError;

    #[test]
    fn account_name() {
        let error = TotpUrlError::AccountName("Laziz:".to_string());
        assert_eq!(
            error.to_string(),
            "Account Name can't contain a colon. \"Laziz:\" contains a colon"
        )
    }

    #[test]
    fn account_name_decoding() {
        let error = TotpUrlError::AccountNameDecoding("Laz&iz".to_string());
        assert_eq!(
            error.to_string(),
            "Couldn't URL decode \"Laz&iz\"".to_string()
        )
    }

    #[test]
    fn algorithm() {
        let error = TotpUrlError::Algorithm("SIKE".to_string());
        assert_eq!(
            error.to_string(),
            "Algorithm can only be SHA1, SHA256 or SHA512, not \"SIKE\"".to_string()
        )
    }

    #[test]
    fn digits() {
        let error = TotpUrlError::Digits("six".to_string());
        assert_eq!(
            error.to_string(),
            "Could not parse \"six\" as a number.".to_string()
        )
    }

    #[test]
    fn digits_number() {
        let error = TotpUrlError::DigitsNumber(5);
        assert_eq!(error.to_string(), "Implementations MUST extract a 6-digit code at a minimum and possibly 7 and 8-digit code. 5 digits is not allowed".to_string())
    }

    #[test]
    fn host() {
        let error = TotpUrlError::Host("hotp".to_string());
        assert_eq!(
            error.to_string(),
            "Host should be totp, not \"hotp\"".to_string()
        )
    }

    #[test]
    fn issuer() {
        let error = TotpUrlError::Issuer("Iss:uer".to_string());
        assert_eq!(
            error.to_string(),
            "Issuer can't contain a colon. \"Iss:uer\" contains a colon".to_string()
        )
    }

    #[test]
    fn issuer_decoding() {
        let error = TotpUrlError::IssuerDecoding("iss&uer".to_string());
        assert_eq!(
            error.to_string(),
            "Couldn't URL decode \"iss&uer\"".to_string()
        )
    }

    #[test]
    fn issuer_mismatch() {
        let error = TotpUrlError::IssuerMistmatch("Google".to_string(), "Github".to_string());
        assert_eq!(error.to_string(), "An issuer \"Google\" could be retrieved from the path, but a different issuer \"Github\" was found in the issuer URL parameter".to_string())
    }

    #[test]
    fn scheme() {
        let error = TotpUrlError::Scheme("https".to_string());
        assert_eq!(
            error.to_string(),
            "Scheme should be otpauth, not \"https\"".to_string()
        )
    }

    #[test]
    fn secret() {
        let error = TotpUrlError::Secret("YoLo".to_string());
        assert_eq!(
            error.to_string(),
            "Secret \"YoLo\" is not a valid non-padded base32 string".to_string()
        )
    }

    #[test]
    fn secret_size() {
        let error = TotpUrlError::SecretSize(112);
        assert_eq!(
            error.to_string(),
            "The length of the shared secret MUST be at least 128 bits. 112 bits is not enough"
                .to_string()
        )
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn step() {
        let error = TotpUrlError::Url(url::ParseError::EmptyHost);
        assert_eq!(
            error.to_string(),
            "Error parsing URL: empty host".to_string()
        )
    }
}
