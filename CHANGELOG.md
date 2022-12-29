# [v1.0](https://github.com/constantoine/totp-rs/releases/tag/v1.0)
## What's Changed
* Fixed wrongful results using hmac-256 and hmac-512 thanks to @ironhaven extensive researches within RFC's in https://github.com/constantoine/totp-rs/pull/12

## What's coming next
- The currently used "qrcode" library is abandonned. Preliminary work showed it was not compatible woth newer versions of the "image" library
- I'd like to take that opportunity to rethink the way the "qr" feature is presented