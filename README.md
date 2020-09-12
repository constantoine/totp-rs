# totp-rs
![Build Status](https://github.com/constantoine/totp-rs/workflows/Rust/badge.svg) ![docs](https://docs.rs/totp-rs/badge.svg)

This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! Default features are kept as lightweight as possible to ensure small binaries and short compilation time

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
totp-rs = "~0.6"
```
You can then do something like:
```Rust
use std::time::SystemTime;
use totp_rs::{Algorithm, TOTP};

let totp = TOTP::new(
    Algorithm::SHA1,
    6,
    1,
    30,
    "supersecret",
);
let time = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH).unwrap()
    .as_secs();
let url = totp.get_url("user@example.com", "my-org.com");
println!("{}", url);
let token = totp.generate(time);
println!("{}", token);
```

### With qrcode generation

Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "~0.6"
features = ["qr"]
```
You can then do something like:
```Rust
use totp_rs::{Algorithm, TOTP};

let totp = TOTP::new(
    Algorithm::SHA1,
    6,
    1,
    30,
    "supersecret",
);
let code = totp.get_qr("user@example.com", "my-org.com")?;
println!("{}", code);
```

### With serde support
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "~0.6"
features = ["serde_support"]
```
