#[cfg(feature = "steam")]
use crate::{Algorithm, Builder};

#[cfg(feature = "steam")]
#[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
impl Builder {
    /// New Builder as created by [Self::new], that is then modified to have the `algorithm`, `digits`, `skew` and `step_duration` options
    /// to the values Steam uses.
    ///
    /// If `otpauth` is enabled, will set `issuer` to `Some("Steam")`.
    #[cfg(feature = "steam")]
    #[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
    pub fn new_steam() -> Self {
        let mut new = Self::new();

        new.algorithm = Algorithm::Steam;
        new.digits = 5;
        new.skew = 1;
        new.step_duration = 30;

        #[cfg(feature = "otpauth")]
        {
            new.issuer = Some("Steam".to_string());
        }

        new
    }
}

#[cfg(all(test, feature = "steam", feature = "otpauth"))]
mod test {
    use crate::Builder;

    #[test]
    #[cfg(feature = "otpauth")]
    fn to_url_steam() {
        let totp = Builder::new_steam()
            .with_secret("TestSecretSuperSecret".into())
            .with_account_name("constantoine".into())
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(
            url.as_str(),
            "otpauth://steam/Steam:constantoine?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=5&algorithm=SHA1&issuer=Steam"
        );
    }
}
