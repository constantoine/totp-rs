#![cfg_attr(all(not(feature = "std"), panic = "abort"), no_std)]
#![cfg_attr(all(not(feature = "std"), panic = "abort"), no_main)]

use totp_rs::{Builder, Secret, Totp};

#[cfg_attr(all(not(feature = "std"), panic = "abort"), unsafe(no_mangle))]
pub fn main() {
    #[cfg(all(not(feature = "std"), panic = "abort"))]
    #[panic_handler]
    fn handler(_info: &core::panic::PanicInfo<'_>) -> ! {
        loop {}
    }

    let secret = Secret::new_stack(*b"12345678901234567890");

    let totp: Totp = Builder::new().with_secret(secret).build().unwrap();
    let _token = totp.generate(12345678);
}
