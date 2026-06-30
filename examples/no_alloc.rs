#![cfg_attr(all(not(feature = "std"), panic = "abort"), no_std)]
#![cfg_attr(all(not(feature = "std"), panic = "abort"), no_main)]

use totp_rs::{Builder, Totp};

#[cfg_attr(all(not(feature = "std"), panic = "abort"), unsafe(no_mangle))]
pub fn main() {
    #[cfg(all(not(feature = "std"), panic = "abort"))]
    #[panic_handler]
    fn handler(_info: &core::panic::PanicInfo<'_>) -> ! {
        loop {}
    }

    let totp: Totp = Builder::new().build().unwrap();
    let _token = totp.generate(12345678);
}
