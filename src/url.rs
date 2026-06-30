use crate::{Algorithm, Builder, Secret, Totp, TotpError};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
};
use url::{Host, Url};

#[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
impl crate::Totp {
    /// Generate a TOTP from the standard otpauth URL
    pub fn from_url<S: AsRef<str>>(url: S) -> Result<Totp, TotpError> {
        let builder = Self::parts_from_url(url)?;

        builder.build()
    }

    /// Generate a TOTP from the standard otpauth URL, using [`Builder::build_noncompliant`] internally
    pub fn from_url_unchecked<S: AsRef<str>>(url: S) -> Result<Totp, TotpError> {
        let builder = Self::parts_from_url(url)?;
        Ok(builder.build_noncompliant())
    }

    /// Parse the TOTP parts from the standard otpauth URL.
    /// It returns a builder with defaults values from [Builder::new] + info from the URL.
    /// Notable exception: A password will not be supplied automatically if `gen_secret` is enabled.
    fn parts_from_url<S: AsRef<str>>(url: S) -> Result<Builder, TotpError> {
        let url = Url::parse(url.as_ref()).map_err(TotpError::UrlParse)?;
        if url.scheme() != "otpauth" {
            return Err(TotpError::InvalidScheme {
                scheme: url.scheme().to_string(),
            });
        }

        let mut builder = match url.host() {
            Some(Host::Domain("totp")) => Ok(Builder::new()),
            #[cfg(feature = "steam")]
            Some(Host::Domain("steam")) => Ok(Builder::new_steam()),
            _ => Err(TotpError::InvalidHost {
                host: url.host().unwrap().to_string(),
            }),
        }?;

        builder = builder.without_secret();

        let path = url.path().trim_start_matches('/');
        let path = percent_decode(path)
            .ok_or_else(|| TotpError::AccountNameDecode {
                account_name: path.to_string(),
            })?
            .to_string();

        let account_name: String;
        let mut issuer: Option<String> = None;
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            builder = builder.with_issuer(parts.0);
            account_name = parts.1.to_owned();
        } else {
            account_name = path;
        }

        let account_name = percent_decode(account_name.as_str())
            .ok_or_else(|| TotpError::AccountNameDecode {
                account_name: account_name.to_string(),
            })?
            .to_string();

        builder = builder.with_account_name(account_name);

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "algorithm" => {
                    let algorithm = Algorithm::try_from(value.to_string())
                        .map_err(|cause| TotpError::InvalidAlgorithm { cause })?;

                    builder = builder.with_algorithm(algorithm);
                }
                "digits" => {
                    let digits = value.parse::<u32>().map_err(|_| TotpError::DigitsParse {
                        digits: value.to_string(),
                    })?;

                    builder = builder.with_digits(digits);
                }
                "period" => {
                    let step_duration = value.parse::<u64>().map_err(|_| TotpError::StepParse {
                        step: value.to_string(),
                    })?;

                    builder = builder.with_step_duration(step_duration);
                }
                "secret" => {
                    let secret =
                        Secret::try_from_base32(value).map_err(|_| TotpError::InvalidSecret)?;

                    builder = builder.with_secret(secret);
                }
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

                    builder = builder.with_issuer(&*param_issuer);
                    issuer = Some(param_issuer);
                }
                _ => {}
            }
        }

        #[cfg(feature = "steam")]
        if url.host().unwrap() == Host::Domain("steam")
            || builder.algorithm == Algorithm::Steam
            || issuer
                .as_deref()
                .is_some_and(|i| i.eq_ignore_ascii_case("steam"))
        {
            builder = builder
                .with_algorithm(Algorithm::Steam)
                .with_digits(5)
                .with_issuer("Steam");
        }

        Ok(builder)
    }

    /// Will generate a standard URL used to automatically add TOTP auths. Usually used with qr codes
    ///
    /// Label and issuer will be URL-encoded if needed be
    /// Secret will be base 32'd without padding, as per RFC.
    pub fn to_url(&self) -> Result<String, TotpError> {
        #[cfg(feature = "otpauth")]
        crate::rfc::assert_account_name_valid(&self.account_name)?;

        #[allow(unused_mut)]
        let mut host = "totp";
        #[cfg(feature = "steam")]
        if self.algorithm == Algorithm::Steam {
            host = "steam";
        }
        let account_name = percent_encode(&self.account_name).to_string();
        let mut params = vec![format!("secret={}", self.secret().to_base32())];
        if self.digits != 6 {
            params.push(format!("digits={}", self.digits));
        }
        if self.algorithm != Algorithm::SHA1 {
            // Steam tokens are computed with HMAC-SHA1, so advertise SHA1 on the
            // wire for compatibility with generic parsers. The `steam` host
            // carries the real semantics.
            #[cfg(feature = "steam")]
            let algorithm = if self.algorithm == Algorithm::Steam {
                "SHA1"
            } else {
                self.algorithm.as_str()
            };
            #[cfg(not(feature = "steam"))]
            let algorithm = self.algorithm.as_str();

            params.push(format!("algorithm={algorithm}"));
        }
        let label = if let Some(issuer) = &self.issuer {
            let issuer = percent_encode(issuer);
            params.push(format!("issuer={}", issuer));
            format!("{}:{}", issuer, account_name)
        } else {
            account_name
        };
        if self.step != 30 {
            params.push(format!("period={}", self.step));
        }

        Ok(format!("otpauth://{}/{}?{}", host, label, params.join("&")))
    }
}

fn percent_decode(input: &str) -> Option<impl core::fmt::Display + Clone + '_> {
    let decoded = percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .ok()?;

    Some(decoded)
}

fn percent_encode(input: &str) -> impl core::fmt::Display + Clone + '_ {
    const URL_INCOMPATIBLE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');

    percent_encoding::utf8_percent_encode(input, URL_INCOMPATIBLE)
}

#[cfg(test)]
mod tests {
    use crate::{Algorithm, Builder, Secret, Totp, TotpError};

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
    fn to_url_without_account_name_reports_missing_not_invalid() {
        // A Totp built for generate/check only (no account name) is valid, but
        // turning it into an otpauth URL must fail.
        let totp = Builder::new().with_secret(GOOD_SECRET).build().unwrap();
        assert_eq!(totp.account_name(), "");
        assert_eq!(totp.to_url().unwrap_err(), TotpError::AccountNameNotSet);
    }

    #[test]
    fn url_for_secret_matches_sha1_without_issuer() {
        let totp = Builder::new()
            .with_account_name(GOOD_ACCOUNT)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();

        let url = totp.to_url();
        assert_eq!(
            url.ok().as_deref(),
            Some(
                "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
            )
        );
    }

    #[test]
    fn url_for_secret_matches_sha1() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name(GOOD_ACCOUNT)
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(
            url.ok().as_deref(),
            Some(
                "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github"
            )
        );
    }

    #[test]
    fn url_for_secret_matches_sha256() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA256)
            .with_account_name(GOOD_ACCOUNT)
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(
            url.ok().as_deref(),
            Some(
                "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github"
            )
        );
    }

    #[test]
    fn url_for_secret_matches_sha512() {
        let totp = Builder::new()
            .with_algorithm(Algorithm::SHA512)
            .with_account_name(GOOD_ACCOUNT)
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(
            url.ok().as_deref(),
            Some(
                "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA512&issuer=Github"
            )
        );
    }

    #[test]
    fn from_url_err() {
        assert!(Totp::from_url("otpauth://hotp/123").is_err());
        assert!(Totp::from_url("otpauth://totp/GitHub:test").is_err());
        assert!(
            Totp::from_url(
                "otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256"
            )
            .is_err()
        );
        assert!(Totp::from_url("otpauth://totp/Github:constantoine%40github.com?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").is_err())
    }

    #[test]
    fn from_url_default() {
        let totp =
            Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
                .unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
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
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
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
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
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
            .with_account_name(GOOD_ACCOUNT)
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
    }

    #[test]
    fn from_url_unknown_param() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256&foo=bar").unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref()
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
            .with_account_name("constantoine")
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
        assert_eq!(&*totp.account_name, "constantoine");
        assert_eq!(&**totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_account_name_issuer_encoded() {
        let totp = Totp::from_url("otpauth://totp/Github%3Aconstantoine?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_account_name("constantoine")
            .with_issuer(GOOD_ISSUER)
            .with_secret(GOOD_SECRET)
            .build()
            .unwrap();
        assert_eq!(totp.to_url(), totp_bis.to_url());
        assert_eq!(&*totp.account_name, "constantoine");
        assert_eq!(&**totp.issuer.as_ref().unwrap(), "Github");
    }

    #[test]
    fn from_url_query_issuer() {
        let totp = Totp::from_url("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
        assert_eq!(&**totp.issuer.as_ref().unwrap(), "GitHub");
    }

    #[test]
    fn from_url_wrong_scheme() {
        let totp = Totp::from_url(
            "http://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256",
        );
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidScheme { .. }));
    }

    #[test]
    fn from_url_wrong_algo() {
        let totp = Totp::from_url(
            "otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=MD5",
        );
        assert!(totp.is_err());
        let err = totp.unwrap_err();
        assert!(matches!(err, TotpError::InvalidAlgorithm { .. }));
    }

    #[test]
    fn from_url_query_different_issuers() {
        let totp = Totp::from_url(
            "otpauth://totp/GitHub:test?issuer=Gitlab&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256",
        );
        assert!(totp.is_err());
        assert!(matches!(
            totp.unwrap_err(),
            TotpError::IssuerMismatch { .. },
        ));
    }

    #[test]
    fn from_url_no_issuer() {
        let totp = Totp::from_url(
            "otpauth://totp/test?&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256",
        ).unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
        );
        assert_eq!(totp.algorithm, Algorithm::SHA256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 60);
        assert_eq!(totp.issuer.as_ref(), None);
    }

    #[cfg(feature = "steam")]
    #[test]
    fn from_steam_format_1() {
        let totp = Totp::from_url(
            "otpauth://totp/Steam:username?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Steam",
        )
        .unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
        );
        assert_eq!(totp.algorithm, Algorithm::Steam);
        assert_eq!(totp.digits, 5);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
        assert_eq!(&**totp.issuer.as_ref().unwrap(), "Steam");
    }

    #[cfg(feature = "steam")]
    #[test]
    fn from_steam_format_2() {
        let totp = Totp::from_url(
            "otpauth://steam/Steam:username?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
        )
        .unwrap();
        assert_eq!(
            Ok(totp.secret()),
            Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").as_ref(),
        );
        assert_eq!(totp.algorithm, Algorithm::Steam);
        assert_eq!(totp.digits, 5);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
        assert_eq!(&**totp.issuer.as_ref().unwrap(), "Steam");
    }

    #[cfg(feature = "steam")]
    #[test]
    fn from_steam_host_authoritative_over_algorithm() {
        // host=steam with no issuer hint and an explicit algorithm=SHA1: the
        // steam host must win over the SHA1 param.
        let totp = Totp::from_url(
            "otpauth://steam/username?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA1",
        )
        .unwrap();
        assert_eq!(totp.algorithm, Algorithm::Steam);
        assert_eq!(totp.digits, 5);
    }
}
