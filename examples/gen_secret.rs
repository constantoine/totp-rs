#![cfg(all(feature = "gen_secret", feature = "std"))]

use totp_rs::{Builder, Totp};

fn main() {
    let totp: Totp = Builder::new().build().unwrap();

    println!("code: {}", totp.generate_current())
}
