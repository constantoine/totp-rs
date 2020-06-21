use std::time::SystemTime;
use totp_rs::{Algorithm, TOTP};

fn main() {
    let username = "example".to_string();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        "supersecret".to_string().into_bytes(),
    );
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
        .as_secs();
    let url = totp.get_url(format!("account:{}", username), "my-org.com".to_string());
    println!("{}", url);
    let token = totp.generate(time);
    println!("{}", token);
}
