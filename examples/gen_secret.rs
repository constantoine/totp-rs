#[cfg(not(feature = "gen_secret"))]
compile_error!("requires feature gen_secret");

use totp_rs::{Secret, TOTP, Algorithm};

fn main () {

    let secret = Secret::generate_rfc_secret();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.as_bytes().unwrap(),
        None,
        "account".to_string(),
    ).unwrap();

    println!(
        "secret plain: {} ; secret base32 {} ; code: {}",
        secret,
        secret.as_base32(),
        totp.generate_current().unwrap()
    )
}
