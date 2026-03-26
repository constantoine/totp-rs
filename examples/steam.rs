#![cfg(all(feature = "steam", feature = "std"))]

use totp_rs::{Builder, Secret, Totp};

fn main() {
    // create TOTP from base32 secret
    let secret_base_32 = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
    let secret = Secret::try_from_base32(secret_base_32).unwrap();
    let totp: Totp = Builder::new_steam()
        .with_secret(secret.clone())
        .build()
        .unwrap();

    println!("base32 {} ; raw {}", secret_base_32, secret);
    println!("code from base32:\t{}", totp.generate_current().unwrap());
}
