use crate::{Algorithm, TotpError, TOTP};

use url::{Host, Url};

#[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
impl crate::TOTP {
    /// Generate a TOTP from the standard otpauth URL
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<TOTP, TotpError> {
        let (algorithm, digits, skew, step, secret, issuer, account_name) =
            Self::parts_from_url(url)?;
        TOTP::new(algorithm, digits, skew, step, secret, issuer, account_name)
    }

    /// Generate a TOTP from the standard otpauth URL, using `TOTP::new_unchecked` internally
    pub fn from_url_unchecked<S: AsRef<str>>(url: S) -> Result<TOTP, TotpError> {
        let (algorithm, digits, skew, step, secret, issuer, account_name) =
            Self::parts_from_url(url)?;
        Ok(TOTP::new_unchecked(
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        ))
    }

    /// Parse the TOTP parts from the standard otpauth URL
    fn parts_from_url<S: AsRef<str>>(
        url: S,
    ) -> Result<(Algorithm, usize, u8, u64, Vec<u8>, Option<String>, String), TotpError> {
        let mut algorithm = Algorithm::SHA1;
        let mut digits = 6;
        let mut step = 30;
        let mut secret = Vec::new();
        let mut issuer: Option<String> = None;
        let mut account_name: String;

        let url = Url::parse(url.as_ref()).map_err(TotpError::UrlParse)?;
        if url.scheme() != "otpauth" {
            return Err(TotpError::InvalidScheme {
                scheme: url.scheme().to_string(),
            });
        }
        match url.host() {
            Some(Host::Domain("totp")) => {}
            #[cfg(feature = "steam")]
            Some(Host::Domain("steam")) => {
                algorithm = Algorithm::Steam;
            }
            _ => {
                return Err(TotpError::InvalidHost {
                    host: url.host().unwrap().to_string(),
                });
            }
        }

        let path = url.path().trim_start_matches('/');
        let path = urlencoding::decode(path)
            .map_err(|_| TotpError::AccountNameDecode {
                value: path.to_string(),
            })?
            .to_string();
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            account_name = parts.1.to_owned();
        } else {
            account_name = path;
        }

        account_name = urlencoding::decode(account_name.as_str())
            .map_err(|_| TotpError::AccountNameDecode {
                value: account_name.to_string(),
            })?
            .to_string();

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                #[cfg(feature = "steam")]
                "algorithm" if algorithm == Algorithm::Steam => {
                    // Do not change used algorithm if this is Steam
                }
                "algorithm" => {
                    algorithm = match value.as_ref() {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => {
                            return Err(TotpError::InvalidAlgorithm {
                                algorithm: value.to_string(),
                            })
                        }
                    }
                }
                "digits" => {
                    digits = value
                        .parse::<usize>()
                        .map_err(|_| TotpError::InvalidDigitsURL {
                            digits: value.to_string(),
                        })?;
                }
                "period" => {
                    step = value
                        .parse::<u64>()
                        .map_err(|_| TotpError::InvalidStepURL {
                            step: value.to_string(),
                        })?;
                }
                "secret" => {
                    secret = base32::decode(
                        base32::Alphabet::Rfc4648 { padding: false },
                        value.as_ref(),
                    )
                    .ok_or_else(|| TotpError::InvalidSecret)?;
                }
                #[cfg(feature = "steam")]
                "issuer" if value.to_lowercase() == "steam" => {
                    algorithm = Algorithm::Steam;
                    digits = 5;
                    issuer = Some(value.into());
                }
                "issuer" => {
                    let param_issuer: String = value.into();
                    if issuer.is_some() && param_issuer.as_str() != issuer.as_ref().unwrap() {
                        return Err(TotpError::IssuerMismatch {
                            path: issuer.as_ref().unwrap().to_string(),
                            query: param_issuer,
                        });
                    }
                    issuer = Some(param_issuer);
                    #[cfg(feature = "steam")]
                    if issuer == Some("Steam".into()) {
                        algorithm = Algorithm::Steam;
                    }
                }
                _ => {}
            }
        }

        #[cfg(feature = "steam")]
        if algorithm == Algorithm::Steam {
            digits = 5;
            step = 30;
            issuer = Some("Steam".into());
        }

        if secret.is_empty() {
            return Err(TotpError::SecretTooShort { bits: 0 });
        }

        Ok((algorithm, digits, 1, step, secret, issuer, account_name))
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    ///
    /// Label and issuer will be URL-encoded if needed be
    /// Secret will be base 32'd without padding, as per RFC.
    pub fn get_url(&self) -> String {
        #[allow(unused_mut)]
        let mut host = "totp";
        #[cfg(feature = "steam")]
        if self.algorithm == Algorithm::Steam {
            host = "steam";
        }
        let account_name = urlencoding::encode(self.account_name.as_str()).to_string();
        let mut params = vec![format!("secret={}", self.get_secret_base32())];
        if self.digits != 6 {
            params.push(format!("digits={}", self.digits));
        }
        if self.algorithm != Algorithm::SHA1 {
            params.push(format!("algorithm={}", self.algorithm));
        }
        let label = if let Some(issuer) = &self.issuer {
            let issuer = urlencoding::encode(issuer);
            params.push(format!("issuer={}", issuer));
            format!("{}:{}", issuer, account_name)
        } else {
            account_name
        };
        if self.step != 30 {
            params.push(format!("period={}", self.step));
        }

        format!("otpauth://{}/{}?{}", host, label, params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Algorithm, TotpError, TOTP};

    #[cfg(feature = "gen_secret")]
    use crate::{Rfc6238, Secret};

    #[test]
    #[cfg(feature = "gen_secret")]
    fn default_values() {
        let totp = TOTP::default();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30)
    }

    #[test]
    fn new_wrong_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github:".to_string()),
            "constantoine@github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(totp.unwrap_err(), TotpError::InvalidIssuer { .. }));
    }

    #[test]
    fn new_wrong_account_name() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine:github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpError::InvalidAccountName { .. }
        ));
    }

    #[test]
    fn new_wrong_account_name_no_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            None,
            "constantoine:github.com".to_string(),
        );
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpError::InvalidAccountName { .. }
        ));
    }

    #[test]
    fn comparison_ok() {
        let reference = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let test = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(reference, test);
    }

    #[test]
    fn url_for_secret_matches_sha1_without_issuer() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            None,
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(
            url.as_str(),
            "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    fn url_for_secret_matches_sha1() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha256() {
        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha512() {
        let totp = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA512&issuer=Github");
    }

    #[test]
    #[cfg(feature = "gen_secret")]
    fn ttl() {
        let secret = Secret::default();
        let totp_rfc = Rfc6238::with_defaults(secret.to_bytes().unwrap()).unwrap();
        let totp = TOTP::from_rfc6238(totp_rfc);
        assert!(totp.is_ok());
    }

    #[test]
    fn ttl_ok() {
        let totp = TOTP::new(
            Algorithm::SHA512,
            6,
            1,
            1,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert!(totp.ttl().is_ok());
    }

    #[test]
    fn from_url_err() {
        assert!(TOTP::from_url("otpauth://hotp/123").is_err());
        assert!(TOTP::from_url("otpauth://totp/GitHub:test").is_err());
        assert!(TOTP::from_url(
            "otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256"
        )
        .is_err());
        assert!(TOTP::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").is_err())
    }

    #[test]
    fn from_url_default() {
        let totp =
            TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
                .unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
    }

    #[test]
    fn from_url_query() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    fn from_url_query_sha512() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA512").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA512);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    fn from_url_to_url() {
        let totp = TOTP::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
    }

    #[test]
    fn from_url_unknown_param() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256&foo=bar").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
    }

    #[test]
    fn from_url_issuer_special() {
        let totp = TOTP::from_url("otpauth://totp/Github%40:constantoine%40github.com?issuer=Github%40&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github@".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github@");
    }

    #[test]
    fn from_url_account_name_issuer() {
        let totp = TOTP::from_url("otpauth://totp/Github:constantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_account_name_issuer_encoded() {
        let totp = TOTP::from_url("otpauth://totp/Github%3Aconstantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "TestSecretSuperSecret".as_bytes().to_vec(),
            Some("Github".to_string()),
            "constantoine".to_string(),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_query_issuer() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(
            totp.secret,
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
            .unwrap()
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
        assert_eq!(totp.issuer.as_ref().unwrap(), "GitHub");
    }

    #[test]
    fn from_url_wrong_scheme() {
        let totp = TOTP::from_url("http://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidScheme { .. }));
    }

    #[test]
    fn from_url_wrong_algo() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=MD5");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidAlgorithm { .. }));
    }

    #[test]
    fn from_url_query_different_issuers() {
        let totp = TOTP::from_url("otpauth://totp/GitHub:test?issuer=Gitlab&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpError::IssuerMismatch { .. },
        ));
    }
}
