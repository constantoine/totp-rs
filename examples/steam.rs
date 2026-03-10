use base32;
use totp_rs::{Builder, Secret, Totp};

#[cfg(feature = "otpauth")]
fn main() {
    // create TOTP from base32 secret
    let secret = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG",
    )
    .unwrap();
    let secret_b32 = Secret::Encoded(s);

    let totp_b32 = Builder::new_steam()
        .with_secret(secret_b32.to_bytes().unwrap())
        .with_account_name("user-account")
        .build()
        .unwrap();

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

#[cfg(not(feature = "otpauth"))]
fn main() {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = Builder::new_steam()
        .with_secret(secret_b32.to_bytes().unwrap())
        .build()
        .unwrap();

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
