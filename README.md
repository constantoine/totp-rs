# totp-rs

This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits!

## How to use

Add it to your `Cargo.toml`:
```toml
[dependencies]
totp-rs = "~0.2"
```
You can then do something like:
```Rust
use totp_rs::{TOTP, Algorithm};
use std::time::SystemTime;

let username = "example".to_string();
let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, "supersecret".to_string().into_bytes());
let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
let url = totp.get_url(format!("account:{}", username), "my-org.com".to_string());
println!("{}", url);
let token = totp.generate(time);
println!("{}", token);
```
