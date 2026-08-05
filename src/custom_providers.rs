#[cfg(feature = "steam")]
use crate::{Algorithm, Builder};

#[cfg(feature = "steam")]
#[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
impl Builder {
    /// New Builder as created by [Self::new], that is then modified to have the `algorithm` and `digits` options
    /// to the values Steam uses.
    ///
    /// It is equivalent to calling [Self::new] followed by [Self::with_algorithm]([Algorithm::Steam]) and [Self::with_digits](5).
    /// If `otpauth` is enabled, will set `issuer` to `Some("Steam")`.
    ///
    /// <div class="warning">
    ///   Calling [self::with_step_duration], [with::with_algorithm] and [with_digits]
    ///   will lead to an incorrect code generation.
    /// </div>
    #[cfg(feature = "steam")]
    #[cfg_attr(docsrs, doc(cfg(feature = "steam")))]
    pub fn new_steam() -> Self {
        let new = Self::new().with_algorithm(Algorithm::Steam).with_digits(5);

        #[cfg(feature = "otpauth")]
        let new = new.with_issuer(Some("Steam"));

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
            .with_secret("TestSecretSuperSecret".as_bytes())
            .with_account_name("constantoine")
            .build()
            .unwrap();
        let url = totp.to_url();
        assert_eq!(
            url.ok().as_deref(),
            Some(
                "otpauth://steam/Steam:constantoine?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=5&algorithm=SHA1&issuer=Steam"
            )
        );
    }
}
