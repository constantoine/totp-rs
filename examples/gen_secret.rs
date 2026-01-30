#[cfg(all(feature = "gen_secret", feature = "otpauth"))]
use totp_rs::{Algorithm, Secret, Totp};

#[cfg(all(feature = "gen_secret", feature = "otpauth"))]
fn main() {
    let secret = Secret::generate_secret();

    let totp = Totp::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        None,
        "account".to_string(),
    )
    .unwrap();

    println!(
        "secret raw: {} ; secret base32 {} ; code: {}",
        secret,
        secret.to_encoded(),
        totp.generate_current().unwrap()
    )
}

#[cfg(not(all(feature = "gen_secret", feature = "otpauth")))]
fn main() {}
