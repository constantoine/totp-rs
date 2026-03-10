#![cfg(not(feature = "otpauth"))]
use totp_rs::{Algorithm, Builder, Secret, Totp};

fn main() {
    let totp = Builder::new().unwrap();

    println!("code: {}", totp.generate_current().unwrap())
}
