#![cfg(feature = "std")]

use totp_rs::{Builder, Totp};

const GOOD_SECRET: &[u8] = "TestSecretSuperSecret".as_bytes();

fn main() {
    let totp: Totp = Builder::new().with_secret(GOOD_SECRET).build().unwrap();

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
