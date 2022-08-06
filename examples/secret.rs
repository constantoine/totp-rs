use totp_rs::{Secret, TOTP, Algorithm};

fn main () {
    // create TOTP from base32 secret
    let secret_b32 = Secret::Base32(String::from("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG"));
    let totp_b32 = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_b32.as_bytes().unwrap(),
        None,
        "account".to_string(),
    ).unwrap();

    println!("base32 {} ; plain {}", secret_b32, secret_b32.as_plain().unwrap());
    println!("code from base32:\t{}", totp_b32.generate_current().unwrap());

    // create TOTP from plain text secret
    let secret_plain = Secret::Plain(String::from("plain-string-secret-123"));
    let totp_plain = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_plain.as_bytes().unwrap(),
        None,
        "account".to_string(),
    ).unwrap();

    println!("plain {} ; base32 {}", secret_plain, secret_plain.as_base32());
    println!("code from plain text:\t{}", totp_plain.generate_current().unwrap());
}
