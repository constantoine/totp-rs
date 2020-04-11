//! This library is a cheap wrapper around otpauth, qrcode and image to seamlessly manage
//! Time-based One-Time Password authentification

use std::time::{SystemTime, UNIX_EPOCH};
use otpauth::TOTP;

use qrcode::QrCode;
use image::Luma;
use base64;

/// Will check if provided code is valid with provided secret, with a tolerance of 15 seconds offest
pub fn verify(code: u32, secret: String) -> bool {
    let auth = TOTP::new(secret);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    for i in 0..2 {
        if auth.verify(code, 30, now - 15 + i * 15) {
            return true;
        }
    }
    false
}

/// Will return a qrcode to automatically add a TOTP as a base64 string
pub fn get_qr(secret: String, mail: String) -> String {
    let auth = TOTP::new(secret);
    let code = QrCode::new(auth.to_uri(format!("account:{}@42l.fr", mail), "42l.fr".to_string())).unwrap();
    let mut vec = Vec::new();
    let encoder = image::png::PNGEncoder::new(&mut vec);
    encoder.encode(&code.render::<Luma<u8>>().build().to_vec(), 360, 360, image::ColorType::L8).unwrap();
    base64::encode(vec)
}
