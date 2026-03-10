use totp_rs::{Builder, Totp};

#[cfg(not(feature = "otpauth"))]
fn main() {
    let totp: Totp = Builder::new().build().unwrap();

    println!("code: {}", totp.generate_current().unwrap())
}

#[cfg(feature = "otpauth")]
fn main() {
    let totp: Totp = Builder::new()
        .with_account_name("Constantoine".to_string())
        .build()
        .unwrap();

    println!("code: {}", totp.generate_current().unwrap())
}
