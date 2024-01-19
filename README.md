# totp-rs
![Build Status](https://github.com/constantoine/totp-rs/workflows/Rust/badge.svg) [![docs](https://docs.rs/totp-rs/badge.svg)](https://docs.rs/totp-rs) [![](https://img.shields.io/crates/v/totp-rs.svg)](https://crates.io/crates/totp-rs) [![codecov](https://codecov.io/gh/constantoine/totp-rs/branch/master/graph/badge.svg?token=Q50RAIFVWZ)](https://codecov.io/gh/constantoine/totp-rs) [![cargo-audit](https://github.com/constantoine/totp-rs/actions/workflows/security.yml/badge.svg)](https://github.com/constantoine/totp-rs/actions/workflows/security.yml)

This library permits the creation of 2FA authentification tokens per TOTP, the verification of said tokens, with configurable time skew, validity time of each token, algorithm and number of digits! Default features are kept as lightweight as possible to ensure small binaries and short compilation time.

It now supports parsing [otpauth URLs](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) into a totp object, with sane default values.

Be aware that some authenticator apps will accept the `SHA256` and `SHA512` algorithms but silently fallback to `SHA1` which will make the `check()` function fail due to mismatched algorithms.

## Features
---
### qr
With optional feature "qr", you can use it to generate a base64 png qrcode. This will enable feature `otpauth`.
### otpauth
With optional feature "otpauth", support parsing the TOTP parameters from an `otpauth` URL, and generating an `otpauth` URL. It adds 2 fields to `TOTP`.
### serde_support
With optional feature "serde_support", library-defined types `TOTP` and `Algorithm` and will be Deserialize-able and Serialize-able.
### gen_secret
With optional feature "gen_secret", a secret will be generated for you to store in database.
### zeroize
Securely zero secret information when the TOTP struct is dropped.
### steam
Add support for Steam TOTP tokens.


# Examples

## Summary

0. [Understanding Secret](#understanding-secret)
1. [Generate a token](#generate-a-token)
2. [Enable qrcode generation](#with-qrcode-generation)
3. [Enable serde support](#with-serde-support)
4. [Enable otpauth url support](#with-otpauth-url-support)
5. [Enable gen_secret support](#with-gensecret)
6. [With RFC-6238 compliant default](#with-rfc-6238-compliant-default)
7. [New TOTP from steam secret](#new-totp-from-steam-secret)

### Understanding Secret
---
This new type was added as a disambiguation between Raw and already base32 encoded secrets.
```Rust
Secret::Raw("TestSecretSuperSecret".as_bytes().to_vec())
```
Is equivalent to
```Rust
Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string())
```
### Generate a token
---
Add it to your `Cargo.toml`:
```toml
[dependencies]
totp-rs = "^5.0"
```
You can then do something like:
```Rust
use std::time::SystemTime;
use totp_rs::{Algorithm, TOTP, Secret};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw("TestSecretSuperSecret".as_bytes().to_vec()).to_bytes().unwrap(),
    ).unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);   
}
```
Which is equivalent to:
```Rust
use std::time::SystemTime;
use totp_rs::{Algorithm, TOTP, Secret};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string()).to_bytes().unwrap(),
    ).unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);   
}
```
### With qrcode generation
---
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^5.3"
features = ["qr"]
```
You can then do something like:
```Rust
use totp_rs::{Algorithm, TOTP, Secret};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string()).to_bytes().unwrap(),
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    ).unwrap();
    let qr_code = totp.get_qr_base64()?;
    println!("{}", qr_code);   
}
```

### With serde support
---
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^5.0"
features = ["serde_support"]
```

### With otpauth url support
---
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^5.0"
features = ["otpauth"]
```
You can then do something like:
```Rust
use totp_rs::TOTP;

fn main() {
    let otpauth = "otpauth://totp/GitHub:constantoine@github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=GitHub";
    let totp = TOTP::from_url(otpauth).unwrap();
    println!("{}", totp.generate_current().unwrap());
}
```

### With gen_secret
---
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^5.3"
features = ["gen_secret"]
```
You can then do something like:
```Rust
use totp_rs::{Algorithm, TOTP, Secret};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::default().to_bytes().unwrap(),
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    ).unwrap();
    let qr_code = totp.get_qr_base64()?;
    println!("{}", qr_code);   
}
```
Which is equivalent to
```Rust
use totp_rs::{Algorithm, TOTP, Secret};

fn main() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::generate_secret().to_bytes().unwrap(),
        Some("Github".to_string()),
        "constantoine@github.com".to_string(),
    ).unwrap();
    let qr_code = totp.get_qr_base64()?;
    println!("{}", qr_code);   
}
```

### With RFC-6238 compliant default
---
You can do something like this
```Rust
use totp_rs::{Algorithm, TOTP, Secret, Rfc6238};

fn main () {
    let mut rfc = Rfc6238::with_defaults(
            Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string()).to_bytes().unwrap(),
        )
        .unwrap();

    // optional, set digits
    rfc.digits(8).unwrap();

    // create a TOTP from rfc
    let totp = TOTP::from_rfc6238(rfc).unwrap();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}
```
With `gen_secret` feature, you can go even further and have all values by default and a secure secret.

Note: With `otpauth` feature, `TOTP.issuer` will be `None`, and `TOTP.account_name` will be `""`. Be sure to set those fields before generating an URL/QRCode
```Rust
fn main() {
    let totp = TOTP::default();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}
```

### New TOTP from steam secret
---
Add it to your `Cargo.toml`:
```toml
[dependencies.totp-rs]
version = "^5.3"
features = ["steam"]
```
You can then do something like:
```Rust
use totp_rs::{TOTP, Secret};

fn main() {
    let totp = TOTP::new_steam(
        Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string()).to_bytes().unwrap(),
    ).unwrap();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);   
}
```