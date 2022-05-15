# totp-rs
![Build Status](https://github.com/constantoine/totp-rs/workflows/Rust/badge.svg) [![docs](https://docs.rs/totp-rs/badge.svg)](https://docs.rs/totp-rs) [![](https://img.shields.io/crates/v/totp-rs.svg)](https://crates.io/crates/totp-rs) [![codecov](https://codecov.io/gh/constantoine/totp-rs/branch/master/graph/badge.svg?token=Q50RAIFVWZ)](https://codecov.io/gh/constantoine/totp-rs) [![cargo-audit](https://github.com/constantoine/totp-rs/actions/workflows/security.yml/badge.svg)](https://github.com/constantoine/totp-rs/actions/workflows/security.yml)

This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! Default features are kept as lightweight as possible to ensure small binaries and short compilation time.

It now supports parsing [otpauth URLs](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) into a totp object, with sane default values.

Be aware that some authenticator apps will accept the `SHA256` and `SHA512` algorithms but silently fallback to `SHA1` which will make the `check()` function fail due to mismatched algorithms.

## Features
---
### qr
With optional feature "qr", you can use it to generate a base64 png qrcode
### serde_support
With optional feature "serde_support", library-defined types will be Deserialize-able and Serialize-able

## How to use
---
Add it to your `Cargo.toml`:
```toml
[dependencies]
totp-rs = "^2.0"
```
You can then do something like:
```Rust
use std::time::SystemTime;
use totp_rs::{Algorithm, TOTP};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        "supersecret",
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    ).unwrap();
    let url = totp.get_url();
    println!("{}", url);
    let token = totp.generate_current().unwrap();
    println!("{}", token);   
}
```

### With qrcode generation

Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^2.0"
features = ["qr"]
```
You can then do something like:
```Rust
use totp_rs::{Algorithm, TOTP};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        "supersecret",
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    ).unwrap();
    let code = totp.get_qr("user@example.com", "my-org.com")?;
    println!("{}", code);   
}
```

### With serde support
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^2.0"
features = ["serde_support"]
```

### With otpauth url support

Add it to your `Cargo.toml`:
```toml
[dependencies]
totp-rs = "^2.0"
```
You can then do something like:
```Rust
use totp_rs::TOTP;

fn main() {
    let otpauth = "otpauth://totp/GitHub:constantoine@github.com?secret=ABC&issuer=GitHub";
    let totp = TOTP::from_url(otpauth).unwrap();
    println!("{}", totp.generate_current().unwrap());
}
```