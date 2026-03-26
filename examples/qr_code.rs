#![cfg(feature = "qr")]

use totp_rs::{Builder, Secret, Totp};

fn main() {
    // create TOTP from base32 secret
    let secret = Secret::try_from_base32("OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG").unwrap();

    let totp: Totp = Builder::new()
        .with_account_name("Constantoine".to_string())
        .with_secret(secret)
        .build()
        .unwrap();

    let qr_code = totp.to_qr_base64().unwrap();

    println!("QR Code (base64): {}", qr_code)
}
