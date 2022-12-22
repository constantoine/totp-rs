use totp_rs::{Rfc6238, TOTP};

#[cfg(feature = "otpauth")]
fn main() {
    let mut rfc = Rfc6238::with_defaults("totp-sercret-123".as_bytes().to_vec()).unwrap();

    // optional, set digits, issuer, account_name
    rfc.digits(8).unwrap();
    rfc.issuer("issuer".to_string());
    rfc.account_name("user-account".to_string());

    // create a TOTP from rfc
    let totp = TOTP::from_rfc6238(rfc).unwrap();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}

#[cfg(not(feature = "otpauth"))]
fn main() {
    let mut rfc = Rfc6238::with_defaults("totp-sercret-123".into()).unwrap();

    // optional, set digits, issuer, account_name
    rfc.digits(8).unwrap();

    // create a TOTP from rfc
    let totp = TOTP::from_rfc6238(rfc).unwrap();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}
