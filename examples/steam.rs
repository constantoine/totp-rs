#[cfg(feature = "steam")]
use totp_rs::{Secret, TOTP};

#[cfg(feature = "steam")]
#[cfg(feature = "otpauth")]
fn main() {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = TOTP::new_steam(secret_b32.to_bytes().unwrap(), "user-account".to_string());

    println!(
        "base32 {} ; raw {}",
        secret_b32,
        secret_b32.to_raw().unwrap()
    );
    println!(
        "code from base32:\t{}",
        totp_b32.generate_current().unwrap()
    );
}

#[cfg(feature = "steam")]
#[cfg(not(feature = "otpauth"))]
fn main() {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = TOTP::new_steam(secret_b32.to_bytes().unwrap());

    println!(
        "base32 {} ; raw {}",
        secret_b32,
        secret_b32.to_raw().unwrap()
    );
    println!(
        "code from base32:\t{}",
        totp_b32.generate_current().unwrap()
    );
}

#[cfg(not(feature = "steam"))]
fn main() {}
