# totp-rs

This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! With additional feature "qr", you can use it to generate a base64 png qrcode.

## How to use

Add it to your `Cargo.toml`:
```toml
[dependencies]
totp-rs = "~0.3"
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
    "supersecret".to_owned().into_bytes(),
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
version = "~0.3"
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
    "supersecret".to_owned().into_bytes(),
);
let code = totp.get_qr("user@example.com", "my-org.com")?;
println!("{}", code);
```
