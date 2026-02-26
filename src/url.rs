use crate::{Algorithm, Builder, Totp, TotpError};

use url::{Host, Url};

#[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
impl crate::Totp {
    /// Generate a TOTP from the standard otpauth URL
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<Totp, TotpError> {
        let builder = Self::parts_from_url(url)?;

        builder.build()
    }

    /// Generate a TOTP from the standard otpauth URL, using `Totp::new_unchecked` internally
    pub fn from_url_unchecked<S: AsRef<str>>(url: S) -> Result<Totp, TotpError> {
        let builder = Self::parts_from_url(url)?;
        Ok(builder.build_noncompliant())
    }

    /// Parse the TOTP parts from the standard otpauth URL.
    /// It returns a builder with defaults values from [Builder::new] + info from the URL.
    /// Notable exception: A password will not be supplied automatically if `gen_secret` is enabled.
    fn parts_from_url<S: AsRef<str>>(url: S) -> Result<Builder, TotpError> {
        let mut builder = Builder::new().with_secret(Vec::new());

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
                builder = builder.with_algorithm(Algorithm::Steam);
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

        let account_name: String;
        let mut issuer: Option<String> = None;
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            builder = builder.with_issuer(issuer.clone());
            account_name = parts.1.to_owned();
        } else {
            account_name = path;
        }

        let account_name = urlencoding::decode(account_name.as_str())
            .map_err(|_| TotpError::AccountNameDecode {
                value: account_name.to_string(),
            })?
            .to_string();

        builder = builder.with_account_name(account_name);

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                #[cfg(feature = "steam")]
                // Do not change used algorithm if this is Steam
                "algorithm" if algorithm == Algorithm::Steam => {}
                #[cfg(not(feature = "steam"))]
                "algorithm" => {
                    let algorithm = match value.as_ref() {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => {
                            return Err(TotpError::InvalidAlgorithm {
                                algorithm: value.to_string(),
                            })
                        }
                    };

                    builder = builder.with_algorithm(algorithm);
                }
                "digits" => {
                    let digits = value
                        .parse::<u32>()
                        .map_err(|_| TotpError::InvalidDigitsURL {
                            digits: value.to_string(),
                        })?;

                    builder = builder.with_digits(digits);
                }
                "period" => {
                    let step_duration =
                        value
                            .parse::<u64>()
                            .map_err(|_| TotpError::InvalidStepURL {
                                step: value.to_string(),
                            })?;

                    builder = builder.with_step_duration(step_duration);
                }
                "secret" => {
                    let secret = base32::decode(
                        base32::Alphabet::Rfc4648 { padding: false },
                        value.as_ref(),
                    )
                    .ok_or_else(|| TotpError::InvalidSecret)?;

                    builder = builder.with_secret(secret);
                }
                #[cfg(feature = "steam")]
                "issuer" if value.to_lowercase() == "steam" => {
                    builder = builder.with_algorithm(Algorithm::Steam);
                }
                #[cfg(not(feature = "steam"))]
                "issuer" => {
                    let param_issuer: String = value.into();
                    if issuer.as_ref().is_some()
                        && param_issuer.as_str() != issuer.as_ref().unwrap()
                    {
                        return Err(TotpError::IssuerMismatch {
                            path: issuer.as_ref().unwrap().to_string(),
                            query: param_issuer,
                        });
                    }

                    issuer = Some(param_issuer);
                    builder = builder.with_issuer(issuer.clone());
                }
                _ => {}
            }
        }

        #[cfg(feature = "steam")]
        if algorithm == Algorithm::Steam {
            builder = builder
                .with_algorithm(Algorithm::Steam)
                .with_digits(5)
                .with_issuer(Some(value.into()));
        }

        Ok(builder)
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    ///
    /// Label and issuer will be URL-encoded if needed be
    /// Secret will be base 32'd without padding, as per RFC.
    pub fn to_url(&self) -> String {
        #[allow(unused_mut)]
        let mut host = "totp";
        #[cfg(feature = "steam")]
        if self.algorithm == Algorithm::Steam {
            host = "steam";
        }
        let account_name = urlencoding::encode(self.account_name.as_str()).to_string();
        let mut params = vec![format!("secret={}", self.to_secret_base32())];
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
    use crate::{Algorithm, Builder, Totp, TotpError};

    const GOOD_SECRET: &[u8] = "TestSecretSuperSecret".as_bytes();
    const GOOD_ISSUER: &str = "Github";
    const GOOD_ACCOUNT: &str = "constantoine@github.com";

    #[test]
    #[cfg(feature = "gen_secret")]
    fn default_values() {
        let totp = Totp::default();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30)
    }

    #[test]
    fn url_for_secret_matches_sha1_without_issuer() {
        let totp = Builder::new()
            .with_account_name(GOOD_ACCOUNT.into())
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();

        let url = totp.to_url();
        assert_eq!(
            url.as_str(),
            "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    fn url_for_secret_matches_sha1() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name(GOOD_ACCOUNT.into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha256() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA256)
            .with_account_name(GOOD_ACCOUNT.into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha512() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA512)
            .with_account_name(GOOD_ACCOUNT.into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA512&issuer=Github");
    }

    #[test]
    fn from_url_err() {
        assert!(Totp::from_url("otpauth://hotp/123").is_err());
        assert!(Totp::from_url("otpauth://totp/GitHub:test").is_err());
        assert!(Totp::from_url(
            "otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256"
        )
        .is_err());
        assert!(Totp::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").is_err())
    }

    #[test]
    fn from_url_default() {
        let totp =
            Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
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
        let totp = Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
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
        let totp = Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA512").unwrap();
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
        let totp = Totp::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name(GOOD_ACCOUNT.into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
    }

    #[test]
    fn from_url_unknown_param() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256&foo=bar").unwrap();
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
    fn from_url_account_name_issuer() {
        let totp = Totp::from_url("otpauth://totp/Github:constantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name("constantoine".into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_account_name_issuer_encoded() {
        let totp = Totp::from_url("otpauth://totp/Github%3Aconstantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name("constantoine".into())
            .with_issuer(Some(GOOD_ISSUER.into()))
            .with_secret(GOOD_SECRET.into())
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
        assert_eq!(totp.account_name, "constantoine");
        assert_eq!(totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_query_issuer() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
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
        let totp = Totp::from_url("http://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidScheme { .. }));
    }

    #[test]
    fn from_url_wrong_algo() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=MD5");
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidAlgorithm { .. }));
    }

    #[test]
    fn from_url_query_different_issuers() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?issuer=Gitlab&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256");
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpError::IssuerMismatch { .. },
        ));
    }
}
