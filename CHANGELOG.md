# [5.7.0](https://github.com/constantoine/totp-rs/releases/tag/v5.7.0) (12/04/2025)
### Breaking changes.
- MSRV has been set to Rust `1.66`.

### Changes
- Updated `base32` crate to `0.5`.
- Updated `constant_time_eq` crate to `0.3`.
- Updated `rand` crate to `0.9`.
- Added a bit of documentation.

### Note
This is probably the last version update before the big `6.0`, which will be a big rewrite, and the `2024` edition.
The goal will be to expose the same feature as before, but in a more harmonized and idiomatic way.

# [5.6.0](https://github.com/constantoine/totp-rs/releases/tag/v5.6.0) (24/07/2024)
### Changes
- [qrcodegen-image](https://crates.io/crates/qrcodegen-image) has now been moved to its own [repo](https://github.com/constantoine/qrcodegen-image).

# [5.5.0](https://github.com/constantoine/totp-rs/releases/tag/v5.5.0) (19/01/2024)
### Changes
- Documentation now indicates required feature.

### Special thanks
* [@AntonnMal](https://github.com/AntonnMal) for his work on #64.

# [5.4.0](https://github.com/constantoine/totp-rs/releases/tag/v5.4.0) (04/10/2023)
### Changes
- `SecretParseError` now implements `std::error::Error`.

### Special thanks
* [@FliegendeWurst](https://github.com/FliegendeWurst) for their work on #62.

# [5.3.0](https://github.com/constantoine/totp-rs/releases/tag/v5.3.0) (10/09/2023)
### What's new
- Creation of a new `qrcodegen-image` subcrate to handle image creation, as the wrapper is actually nice and could be used in placed not related to `totp-rs`. (#61)

### Changes
- `TOTP::get_qr` was deprecated in favour of `TOTP::get_qr_base64` and `TOTP::get_qr_png`. 

### Special thanks
* [@tmpfs](https://github.com/tmpfs) for their work on #60 and implementation in #61.

# [5.2.0](https://github.com/constantoine/totp-rs/releases/tag/v5.2.0) (10/08/2023)
### Changes
- Updated `url` crate to `2.4`.

# [5.1.0](https://github.com/constantoine/totp-rs/releases/tag/v5.1.0) (15/07/2023)
### What's new
- Added some more documentation.

### Fix
- Removed unnecessary allocation for `Secret.Display` for the `Raw` variant.

# [5.0.2](https://github.com/constantoine/totp-rs/releases/tag/v5.0.1) (15/05/2023)
### Fix
- Fix skew overflowing if value is over 128.

### Special thanks
* [@carl-wallace](https://github.com/carl-wallace) for discovering #58.

# [5.0.1](https://github.com/constantoine/totp-rs/releases/tag/v5.0.1) (31/03/2023)
### Changes
- Normalize dependencies specifications since cargo uses range dependency by default.

### Special thanks
* [@bestia-dev](https://github.com/bestia-dev) for pointing out discrepancies in my dependency requirements.

# [5.0](https://github.com/constantoine/totp-rs/releases/tag/v5.0) (28/03/2023)
### Breaking changes.
- MSRV has been set to Rust `1.61`.
- Removed `SecretParseError::Utf8Error`.

### Changes
- Updated `base64` to `0.21`.
- Updated `url` to `2.3`.
- Updated `zeroize` to `1.6`.

### Note
This major release is a very small one, and is mostly here to respect semver. No major change was done, it is mostly maintenance and cleanup.

### Special thanks
* [@bestia-dev](https://github.com/bestia-dev) for opening #55.

# [4.2](https://github.com/constantoine/totp-rs/releases/tag/v4.2) (14/01/2023)
### Changes
- Optionnals parameters in generated URLs are no longer present if their're the default value. (#49)

### Fix
- The issuer part of the Path when using the couple Issuer:AccountName wasn't cut correctly if the `:` was URL-encoded. (#50)

### Special thanks
* [@timvisee](https://github.com/timvisee) for their work on #49 and discovering the bug leading to #50.

# [4.1](https://github.com/constantoine/totp-rs/releases/tag/v4.1) (06/01/2023)
### What's new
- Add a "steam" feature which adds support for steam's non-standard totp.
- Add `_unchecked` variants for `TOTP::new` and `TOTP::from_url`, which skip certain checks like key_size and digit numbers.

### Special thanks
* [@colemickens](colemickens) for opening #45.
* [@timvisee](https://github.com/timvisee) for their work on #47 and #48, implementing an idea from #44 and working on #45.

# [4.0](https://github.com/constantoine/totp-rs/releases/tag/v4.0) (29/12/2022)
### What's new
- Default features have been set to none.

### Changes
- MSRV has been set to Rust `1.59`.
- Updated `base64` crate to `0.20`.

### Breaking changes
- This was a relic from the beggining of the library, but `TOTP` is no longer generic. In my opinion, while having been used in the past for some historical reasons, the generic was mostly useless as almost everyone just used bytes as a secret, prevented us from doing some work like the `zeroize` feature, and overall made it more complex to new users than it needed to be.

### Special thanks
* [@tmpfs](https://github.com/tmpfs)  for the work done on #40.
* [@timvisee](https://github.com/timvisee) for their feedback on #40.

## Note
This is the last release for 2022. This project has thus far been a wild ride. Originally intended for a non-profit organization, it gained traction outside of it, and soon became one the projects I'm the most proud of. It has been a pleasure learning from amazing people, and getting precious feedback from real life users. The open-source community has always been a special place to me, and being able to put in the hours to finally give something back has been, is, an amazing opportunity.

The year 2023 should see a lot less of breaking changes, as the library slowly approaches a form most users can happily use. This doesn't mean the library will stop being maintained, but I (hopefully) will stop breaking your stuff so often.

As always for every new realease, please report any issue encountered while updating totp-rs to `4.0.0`.

# [3.1](https://github.com/constantoine/totp-rs/releases/tag/v3.1) (03/11/2022)
### What's new
- `get_qr()` now returns a `String` as an error.
- `TOTP` now implements `core::fmt::Display`
- `Rfc6238Error` and `TotpUrlError` now implement `std::error::Error`

### CI
- Add better coverage thanks to `llvm-tools-preview` and `grcov`

### Style
- Finally `cargo fmt`'d the whole repo

### Special thanks
* [@tmpfs](https://github.com/tmpfs)  for making me notice #41.

# [3.0.1](https://github.com/constantoine/totp-rs/releases/tag/v3.0.1) (13/08/2022)
### Fixes
* `TotpUrlError` was unexported. This is now fixed. (#29)
* `base32` was reexported instead. It is now private, and will need to be an explicit dependency for the user to encore/decode base32 data.

### Changes
* `Secret` comparison is now done in constant time.

### Special thanks
* [@alexanderkja](https://github.com/alexanderkjall) for discovering #29.

# [3.0](https://github.com/constantoine/totp-rs/releases/tag/v3.0) (09/08/2022)
### New features
* Secret handling is now less error prone thanks to #25
* Totp now implements the `Default` trait, which will generate a strong secret, and have sane default values according to RFC-6238 like #26
* `Rfc6238` struct is exposed for easy Totp building
* `Totp.ttl` convenience method will tell remaining validity time of token (not taking skew into account)

### New dependency
* [gen_secret] uses `rand` to generate a secret

### Breaking
* TotpUrlError now contain a string explaining. Inspired by #23
* Totp fields `issuer` and `account_name` won't be present anymore if feature `otpauth` isn't enabled
* The secret and digits field will now be validated for SecretSize (>= 128 bits)

### Special thanks
* [@sacovo](https://github.com/sacovo)for opening #23, from which the TotpUrlError rework was inspired
* [@steven89](https://github.com/steven89) for the tremendous work and back and forth provided with #24 #25 and #26 

## Note
This has been, I think, the update containing the most work. While a lot of unit testing have been done, and test cases added, coverage seems to have dropped. Please report any issue encountered while updating totp-rs to 3.0.0

# [2.1](https://github.com/constantoine/totp-rs/releases/tag/v2.1) (16/06/2022)
### New dependency
* [otpauth] now uses `urlencoding`, which has no dependencies, to url-encode and url-decode values. Because doing this with the `url` library was kind of awkward.

### Fixes
* Bug where your issuer would be incorrectly prefixed with a /, and comparison with the issuer parameter would fail.
* Bug where the issuer and account name in path would not be correctly url decoded in path, but correctly decoded in url query.

### Special thanks
@wyhaya for discovering the first problem in #21 

# [2.0](https://github.com/constantoine/totp-rs/releases/tag/v2.0) (30/05/2022)
### What changed
- `issuer` and `account_name` are now members of TOTP, and thus are not used anymore as function parameters for methods
- `from_url()` now extracts issuer and label
- Method `get_url()` now needs `otpauth` feature
- Method `get_url()` now produces more correct urls
- Methods `next_step(time: u64)` and `next_step_current` will return the timestamp of the next step's start
- Feature `qr` enables feature `otpauth`

### Special thanks
- @wyhaya for giving ideas and feedback for this release

# [1.4](https://github.com/constantoine/totp-rs/releases/tag/v1.4) (06/05/2022)
## What's changed
* Added url dependency for `otpauth` feature, which adds a `from_url` function to parse a `TOTP` object from url. Thanks to @wyhaya (https://github.com/constantoine/totp-rs/pull/19)

# [1.3](https://github.com/constantoine/totp-rs/releases/tag/v1.3) (06/05/2022)
## What's changed
* Added helper functions `generate_current` and  `check_current`. Thanks to @wyhaya (https://github.com/constantoine/totp-rs/pull/17)
* Clarified output format of get_qr in the docs

# [1.2.1](https://github.com/constantoine/totp-rs/releases/tag/v1.2.1) (05/05/2022)
## What's changed
* Disabled default image features to only enable png

# [1.2](https://github.com/constantoine/totp-rs/releases/tag/v1.2) (05/05/2022)
## What's changed
* Bumped "image" version to 0.24
* Removed "qrcode" library, which was abandoned years ago, to "qrcodegen", which is actively maintained

# [1.1](https://github.com/constantoine/totp-rs/releases/tag/v1.1) (24/04/2022)
## What's changed
* Mitigated possible timing attack as noticed per @gleb-chipiga in https://github.com/constantoine/totp-rs/issues/13
* Added PartialEq support for TOTP<T> and PartialEq + Eq support for Algorithm, suggestion from @gleb-chipiga in https://github.com/constantoine/totp-rs/issues/14

# [1.0](https://github.com/constantoine/totp-rs/releases/tag/v1.0) (15/04/2022)
## What's Changed
* Fixed wrongful results using hmac-256 and hmac-512 thanks to @ironhaven extensive researches within RFC's in https://github.com/constantoine/totp-rs/pull/12

## What's coming next
- The currently used "qrcode" library is abandonned. Preliminary work showed it was not compatible woth newer versions of the "image" library
- I'd like to take that opportunity to rethink the way the "qr" feature is presented
