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

With optional feature "otpauth", support parsing the TOTP parameters from an `otpauth` URL, and generating an `otpauth` URL. It adds 2 fields to `Totp`.

### serde

With optional feature "serde", library-defined types `Totp`, `Algorithm` and `Secret` will be Deserialize-able and Serialize-able.

### gen_secret

With optional feature "gen_secret", a secret will be generated for you to store in database.

### zeroize

Securely zero secret information when the TOTP struct is dropped.

### steam

Add support for Steam TOTP tokens.

### migration

Enabled by default. Provides deprecated aliases and shims for the 5.7.x API so existing code keeps compiling while you port it to the 6.0 `Builder` API (see [MIGRATION.md](MIGRATION.md)). Disable it with `default-features = false` once you have finished migrating to turn any remaining 5.x calls into hard errors.

## Examples

### Summary

0. [Understanding Secret](#understanding-secret)
1. [Generate a token](#generate-a-token)
2. [Enable qrcode generation](#with-qrcode-generation)
3. [Enable otpauth url support](#with-otpauth-url-support)
4. [Enable gen_secret support](#with-gen_secret)
5. [With RFC-6238 compliant default](#with-rfc-6238-compliant-default)
6. [New TOTP from steam secret](#new-totp-from-steam-secret)

### Understanding Secret

---
`Secret` is an opaque type holding the secret's raw bytes. You can build one
either from raw bytes or from a base32-encoded string; both yield the same value.

```Rust
Secret::from("TestSecretSuperSecret".as_bytes())
```

Is equivalent to:

```Rust
Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap()
```

### Generate a token

---
Add it to your `Cargo.toml`:

```toml
[dependencies]
totp-rs = "^6.0"
```

You can then do something like:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::from("TestSecretSuperSecret".as_bytes()))
        .build()
        .unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

Which is equivalent to:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        .build()
        .unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

`generate_current` returns a `Token`. It implements `Display`, so it prints
directly; call `.to_string()` if you need an owned `String`.

### With qrcode generation

---
Add it to your `Cargo.toml`:

```toml
[dependencies.totp-rs]
version = "^6.0"
features = ["qr"]
```

You can then do something like:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        .with_issuer("Github")
        .with_account_name("constantoine@github.com")
        .build()
        .unwrap();
    let qr_code = totp.to_qr_base64().unwrap();
    println!("{}", qr_code);
}
```

### With otpauth url support

---
Add it to your `Cargo.toml`:

```toml
[dependencies.totp-rs]
version = "^6.0"
features = ["otpauth"]
```

You can then do something like:

```Rust
use totp_rs::Totp;

fn main() {
    let otpauth = "otpauth://totp/GitHub:constantoine@github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=GitHub";
    let totp = Totp::from_url(otpauth).unwrap();
    println!("{}", totp.generate_current().unwrap());
}
```

### With gen_secret

---
Add it to your `Cargo.toml`:

```toml
[dependencies.totp-rs]
version = "^6.0"
features = ["gen_secret"]
```

With `gen_secret`, `Builder::new()` already holds a freshly generated secret, so
you can build a `Totp` without supplying one:

```Rust
use totp_rs::{Builder, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .build()
        .unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

Which is equivalent to setting the secret explicitly:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::generate())
        .build()
        .unwrap();
    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

### With RFC-6238 compliant default

---
`Builder::new()` already starts from RFC-6238 compliant defaults (SHA1, 6 digits,
skew of 1, 30 second step), and `build()` enforces that compliance. So the only
mandatory step is providing a secret:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        .build()
        .unwrap();

    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

is equivalent to:

```Rust
use totp_rs::{Algorithm, Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .build()
        .unwrap();

    let token = totp.generate_current().unwrap();
    println!("{}", token);
}
```

You can override each property individually:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main () {
    let totp: Totp = Builder::new()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        // optional, override a default; 8 digits is still RFC-compliant
        .with_digits(8)
        .build()
        .unwrap();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}
```

You can ignore compliance checks by using `Builder::build_noncompliant`.
Note that the checks are here for a reason, and unless you know what you're doing, you should really not have a lot of usecases for this one.

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main () {
    let totp: Totp = Builder::new()
        // Secret is too short to be compliant.
        .with_secret(Secret::try_from_base32("KRSXG5C").unwrap())
        // Cannot divide by zero.
        .with_step_duration(0)
        .build_noncompliant();

    // Panic here because you can't divide by zero.
    let code = totp.generate_current().unwrap();
}
```

With `gen_secret` feature, you can go even further and have all values by default and a secure secret.

Note: With `otpauth` feature, the issuer defaults to `None` and the account name to `""`. Be sure to set them with `Builder::with_issuer` and `Builder::with_account_name` before generating an URL/QRCode.

```Rust
fn main() {
    let totp = Totp::default();
    let code = totp.generate_current().unwrap();
    println!("code: {}", code);
}
```

### New TOTP from steam secret

---
Add it to your `Cargo.toml`:

```toml
[dependencies.totp-rs]
version = "^6.0"
features = ["steam"]
```

You can then do something like:

```Rust
use totp_rs::{Builder, Secret, Totp};

fn main() {
    let totp: Totp = Builder::new_steam()
        .with_secret(Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ").unwrap())
        .build()
        .unwrap();
    let code = totp.generate_current().unwrap();
    println!("{}", code);
}
```
