use totp_rs::{Algorithm, Secret, TOTP};

#[cfg(feature = "otpauth")]
fn main() {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_b32.to_bytes().unwrap(),
        Some("issuer".to_string()),
        "user-account".to_string(),
    )
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

    // create TOTP from raw binary value
    let secret = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];
    let secret_raw = Secret::Raw(secret.to_vec());
    let totp_raw = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_raw.to_bytes().unwrap(),
        Some("issuer".to_string()),
        "user-account".to_string(),
    )
    .unwrap();

    println!("raw {} ; base32 {}", secret_raw, secret_raw.to_encoded());
    println!(
        "code from raw secret:\t{}",
        totp_raw.generate_current().unwrap()
    );
}

#[cfg(not(feature = "otpauth"))]
fn main() {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Encoded(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_b32.to_bytes().unwrap()).unwrap();

    println!(
        "base32 {} ; raw {}",
        secret_b32,
        secret_b32.to_raw().unwrap()
    );
    println!(
        "code from base32:\t{}",
        totp_b32.generate_current().unwrap()
    );

    // create TOTP from raw binary value
    let secret = [
        0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x73, 0x65,
        0x63, 0x72, 0x65, 0x74, 0x2d, 0x31, 0x32, 0x33,
    ];
    let secret_raw = Secret::Raw(secret.to_vec());
    let totp_raw = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_raw.to_bytes().unwrap()).unwrap();

    println!("raw {} ; base32 {}", secret_raw, secret_raw.to_encoded());
    println!(
        "code from raw secret:\t{}",
        totp_raw.generate_current().unwrap()
    );
}
