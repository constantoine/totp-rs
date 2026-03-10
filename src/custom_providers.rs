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
            new.issuer = Some("Steam");
        }

        new
    }
}

#[cfg(all(test, feature = "steam"))]
mod test {
    #[cfg(feature = "otpauth")]
    use super::*;

    #[test]
    #[cfg(feature = "otpauth")]
    fn to_url_steam() {
        let totp = Totp::new_steam("TestSecretSuperSecret".into(), "constantoine".into());
        let url = totp.to_url();
        assert_eq!(url.as_str(), "otpauth://steam/Steam:constantoine?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=5&algorithm=SHA1&issuer=Steam");
    }
}
