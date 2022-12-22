use totp_rs::{Algorithm, TOTP};

#[cfg(not(feature = "otpauth"))]
fn main() {
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "my-secret".as_bytes().to_vec()).unwrap();

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
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        "my-secret".as_bytes().to_vec(),
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    )
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
