# Changelog

## [1.4.0](https://github.com/constantoine/totp-rs/releases/tag/qrcodegen-image%2Fv1.4.0) (08/03/2024)

### What's new

- `draw_canvas` is now 15%(!) faster on my machine after optimizing the "drawing_square" loop.
- Updated `base64` crate to `0.22`.

## [1.3.0](https://github.com/constantoine/totp-rs/releases/tag/qrcodegen-image%2Fv1.3.0) (19/01/2024)

### What's new

- `draw_canvas` is now 70%(!) faster on my machine after optimizing the "drawing_square" loop.

## [1.2.0](https://github.com/constantoine/totp-rs/releases/tag/qrcodegen-image%2Fv1.2.0) (14/09/2023)

### What's new

- Added benchmarks for `draw_canvas`.
- `draw_canvas` is now 150%(!) faster on my machine after optimizing the "border" loop.

## [1.1.0](https://github.com/constantoine/totp-rs/releases/tag/qrcodegen-image%2Fv1.1.0) (11/09/2023)

### What's new

- Added documentation for `draw_png` and `draw_base64`.
- Add changelog.

## [1.0.0](https://github.com/constantoine/totp-rs/releases/tag/qrcodegen-image%2Fv1.0.0) (10/09/2023)

### What's new

- Creation of a new `qrcodegen-image` subcrate to handle image creation, as the wrapper is actually nice and could be used in placed not related to `totp-rs`. (#61)

### Special thanks

- [@tmpfs](https://github.com/tmpfs) for their work on #60 and implementation in #61.
