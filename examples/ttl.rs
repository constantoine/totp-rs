use totp_rs::Builder;

const GOOD_SECRET: &[u8] = "TestSecretSuperSecret".as_bytes();

#[cfg(not(feature = "otpauth"))]
fn main() {
    let totp = Builder::new()
        .with_secret(GOOD_SECRET.into())
        .build()
        .unwrap();

    loop {
        println!(
            "code {}\t ttl {}\t valid until: {}",
            totp.generate_current().unwrap(),
            totp.ttl().unwrap(),
            totp.next_step_current().unwrap()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(feature = "otpauth")]
fn main() {
    let totp = Builder::new()
        .with_account_name("constantoine@github.com".to_string())
        .with_issuer(Some("Github".to_string()))
        .with_secret(GOOD_SECRET.into())
        .build()
        .unwrap();

    loop {
        println!(
            "code {}\t ttl {}\t valid until: {}",
            totp.generate_current().unwrap(),
            totp.ttl().unwrap(),
            totp.next_step_current().unwrap()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
