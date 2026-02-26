use crate::TotpError;

// Check that the number of digits is RFC-compliant.
// (between 6 and 8 inclusive).
pub fn assert_digits(digits: u32) -> Result<(), TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits { digits: digits });
    }

    Ok(())
}

// Check that the secret is AT LEAST 128 bits long, as per the RFC's requirements.
// It is still RECOMMENDED to have an at least 160 bits long secret.
pub fn assert_secret_length(secret: &[u8]) -> Result<(), TotpError> {
    if secret.as_ref().len() < 16 {
        return Err(TotpError::SecretTooShort {
            bits: secret.as_ref().len() * 8,
        });
    }

    Ok(())
}

// Checks that account_name is not empty AND doesn't contain `:`.
#[cfg(feature = "otpauth")]
pub fn assert_account_name_valid(account_name: &String) -> Result<(), TotpError> {
    if account_name.is_empty() || account_name.contains(':') {
        return Err(TotpError::InvalidAccountName {
            value: account_name.clone(),
        });
    }

    Ok(())
}

// Checks that issuer is either unset (not recommended) or doesn't contain `:`.
#[cfg(feature = "otpauth")]
pub fn assert_issuer_valid(issuer: &Option<String>) -> Result<(), TotpError> {
    if let Some(ref issuer) = issuer {
        if issuer.contains(':') {
            return Err(TotpError::InvalidIssuer {
                value: issuer.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Totp, TotpError};

    const GOOD_SECRET: &str = "01234567890123456789";
    #[cfg(feature = "otpauth")]
    const ISSUER: Option<&str> = None;
    #[cfg(feature = "otpauth")]
    const ACCOUNT: &str = "valid-account";
    #[cfg(feature = "otpauth")]
    const INVALID_ACCOUNT: &str = ":invalid-account";
}
