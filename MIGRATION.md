# Migrating from 5.7.x to 6.0.0

Version 6.0.0 changes the public API, adds `no_std` support, and replaces the
secret and error types. This guide lists the breaking changes and how to update
your code.

## Summary

- `TOTP` is now `Totp`, built with a `Builder` instead of `TOTP::new(...)`.
- `Secret` is no longer a `Raw`/`Encoded` enum: use `Secret::from(bytes)` and
  `Secret::try_from_base32(...)`.
- `generate`/`generate_current` return a [`Token`] instead of a `String`.
- `check`/`check_current` return `Option<u64>`/`Result<Option<u64>>` (the
  matched step counter) instead of `bool`/`Result<bool>`.
- All errors are now the single `TotpError` type.
- The `serde_support` feature is now `serde`, and `std` is enabled by default.

## The migration module

The `migration` feature (on by default) provides deprecated aliases and shims
so most 5.x code keeps compiling, each with a `#[deprecated]` note pointing at
the replacement. Once you have finished porting, disable it
(`default-features = false`, then re-enable the features you use) to turn the
remaining 5.x calls into hard errors:

| 5.x                                                                                   | 6.0 replacement                                                 |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `TOTP`                                                                                | `Totp`                                                          |
| `Rfc6238`                                                                             | `Builder`                                                       |
| `Rfc6238Error`, `TotpUrlError`                                                        | `TotpError`                                                     |
| `TOTP::new(...)` / `new_unchecked(...)`                                               | `Builder::new()` + `.with_*` + `build()`/`build_noncompliant()` |
| `TOTP::from_rfc6238(b)`                                                               | `Builder::build()`                                                     |
| `TOTP::new_steam(...)`                                                                | `Builder::new_steam()` + `.with_*`                              |
| `totp.get_secret_base32()`                                                            | `totp.secret().to_base32()`                                     |
| `totp.get_url()`                                                                      | `totp.to_url()`                                                 |
| `totp.get_qr_base64()` / `get_qr_png()`                                               | `totp.to_qr_base64()` / `to_qr_png()`                           |
| `Secret::generate_secret()`                                                           | `Secret::generate()`                                            |
| `secret.to_bytes()`                                                                   | `secret.as_bytes()`                                             |
| `Rfc6238::with_defaults(s)`                                                           | `Builder::new().with_secret(s)`                                 |

These keep building with warnings, so you can migrate incrementally. The five
changes below cannot be shimmed, because the method name is unchanged and only
the return type differs. They surface as type errors at the call site.

## Breaking changes with no shim

### `generate` / `generate_current` return `Token`

```rust
// 5.x
let code: String = totp.generate_current().unwrap();

// 6.0 Token implements Display:
let token = totp.generate_current()?;
println!("{token}");
// For a String:
let code: String = totp.generate_current()?.to_string();
```

`Token` compares in constant time and is stack-allocated. To check a token,
use [`check`] rather than formatting it to a `String` and comparing strings.

### `check` / `check_current` return the matched step

```rust
// 5.x
if totp.check_current(&token).unwrap() {
    // valid
}

// 6.0 Option<u64> is Some(step) when valid:
if totp.check_current(&token)?.is_some() {
    // valid
}
// Or use the matched step index:
if let Some(step) = totp.check_current(&token)? {
    // valid; `step` is the step counter that matched
}
```

`check` returns `Option<u64>` and `check_current` returns
`Result<Option<u64>, SystemTimeError>`.

### `sign` returns `impl AsRef<[u8]>`

```rust
// 5.x
let sig: Vec<u8> = totp.sign(time);

// 6.0
let sig = totp.sign(time);
let bytes: &[u8] = sig.as_ref();
```

## Constructing a `Totp`

```rust
// 5.x
use totp_rs::{Algorithm, Secret, TOTP};
let totp = TOTP::new(
    Algorithm::SHA1,
    6,
    1,
    30,
    Secret::Raw("TestSecretSuperSecret".as_bytes().to_vec()).to_bytes().unwrap(),
    Some("Github".to_string()),
    "constantoine@github.com".to_string(),
)?;

// 6.0
use totp_rs::{Algorithm, Builder};
let totp = Builder::new()
    .with_algorithm(Algorithm::SHA1)
    .with_secret("TestSecretSuperSecret".as_bytes())
    .with_issuer("Github")
    .with_account_name("constantoine@github.com")
    .build()?;
```

`build()` validates RFC compliance (digit count, secret length, step ≠ 0,
issuer/account-name characters). `build_noncompliant()` skips those checks,
matching the old `new_unchecked` behaviour.

### From an `Rfc6238` builder

```rust
// 5.x
let mut rfc = Rfc6238::with_defaults(secret)?;
rfc.digits(8)?;
let totp = TOTP::from_rfc6238(rfc)?;

// 6.0
let totp = Builder::new().with_secret(secret).with_digits(8).build()?;
```

### Steam

```rust
// 5.x
let totp = TOTP::new_steam(secret, "account".to_string());

// 6.0
let totp = Builder::new_steam()
    .with_secret(secret)
    .with_account_name("account")
    .build()?;
```

## `Secret`

The `Secret::Raw` / `Secret::Encoded` enum is replaced by an opaque type holding
bytes.

```rust
// 5.x
let raw = Secret::Raw(bytes.to_vec());
let encoded = Secret::Encoded("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ".to_string());
let bytes = raw.to_bytes().unwrap();

// 6.0
let raw = Secret::from(bytes);                                  // &[u8], Vec<u8>, [u8; N], Box<[u8]>
let encoded = Secret::try_from_base32("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")?;
let bytes: &[u8] = raw.as_bytes();
let base32: String = raw.to_base32();
```

- `Secret::generate_secret()`: `Secret::generate()` (feature `gen_secret`).
- `Secret` compares in constant time and zeroizes on drop with the `zeroize`
  feature.
- `SecretParseError` keeps the `ParseBase32` variant.

## Errors

`TotpUrlError` and `Rfc6238Error` are replaced by a single `#[non_exhaustive]`
`TotpError`. Match on its variants (e.g. `TotpError::SecretTooShort { bits }`,
`TotpError::InvalidDigits { digits }`, `TotpError::IssuerMismatch { .. }`)
instead of the old per-area types.

## Serialized data (`serde`)

The serialized representation changed, so data persisted by 5.7.x is **not**
guaranteed to deserialize under 6.0. Re-issue or re-serialize stored values.

- The `secret` field was a `Vec<u8>` on `TOTP`; it is now a [`Secret`] on `Totp`,
  serialized as a single flat byte array.
- `digits` changed from `usize` to `u32` and `skew` from `u8` to `u16`, which
  width-sensitive formats (e.g. `bincode`) will reject.

## Feature flags

- `serde_support` was renamed to `serde`.
- `std` is now a default feature. For `no_std`, set `default-features = false`
  and enable what you need (`otpauth` and `gen_secret` both work without `std`).

## Toolchain

- MSRV raised from `1.66` to `1.88`.
- Edition is now `2024`.
