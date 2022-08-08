#[cfg(not(feature = "gen_secret"))]
compile_error!("requires feature gen_secret");

use totp_rs::{Secret, TOTP, Algorithm};

fn main () {

    let secret = Secret::generate_secret();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        None,
        "account".to_string(),
    ).unwrap();

    println!(
        "secret raw: {} ; secret base32 {} ; code: {}",
        secret,
        secret.to_encoded(),
        totp.generate_current().unwrap()
    )
}
