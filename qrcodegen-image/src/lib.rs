//! Utility functions for drawing QR codes generated using `qrcodegen`
//! to a canvas provided by the `image` crate.
use image::Luma;

pub use image;
pub use qrcodegen;

/// Draw a QR code to an image buffer.
pub fn draw_canvas(qr: qrcodegen::QrCode) -> image::ImageBuffer<Luma<u8>, Vec<u8>> {
    let size = qr.size() as u32;
    // "+ 8 * 8" is here to add padding (the white border around the QRCode)
    // As some QRCode readers don't work without padding
    let image_size = size * 8 + 8 * 8;
    let mut canvas = image::GrayImage::from_pixel(image_size, image_size, Luma([255]));

    let raw = canvas.as_mut();

    // The QR inside the white border
    for x_qr in 0..size {
        for y_qr in 0..size {
            if !qr.get_module(x_qr as i32, y_qr as i32) {
                continue
            }

            // Multiply coordinates by width of pixels
            // And take into account the 8*4 padding on top and left side
            let x_start = x_qr * 8 + 8 * 4;
            let y_start = y_qr * 8 + 8 * 4;

            // Draw a 8-pixels-wide square
            for y_img in y_start..y_start + 8 {
                let start = (x_start + y_img * image_size) as usize;
                raw[start..start + 8].copy_from_slice(&[0; 8]);
            }
        }
    }
    canvas
}

/// Draw text to a PNG QR code.
///     
/// # Errors
///
/// This will return an error in case the URL gets too long to encode into a QR code.
/// This would require the get_url method to generate an url bigger than 2000 characters,
/// Which would be too long for some browsers anyway.
///
/// It will also return an error in case it can't encode the qr into a png. This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly.
pub fn draw_png(text: &str) -> Result<Vec<u8>, String> {
    use image::ImageEncoder;

    let mut vec = Vec::new();

    let qr: Result<qrcodegen::QrCode, String> =
        match qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium) {
            Ok(qr) => Ok(qr),
            Err(err) => Err(err.to_string()),
        };

    if qr.is_err() {
        return Err(qr.err().unwrap());
    }

    let code = qr?;

    // "+ 8 * 8" is here to add padding (the white border around the QRCode)
    // As some QRCode readers don't work without padding
    let image_size = (code.size() as u32) * 8 + 8 * 8;

    let canvas = draw_canvas(code);

    // Encode the canvas into a PNG
    let encoder = image::codecs::png::PngEncoder::new(&mut vec);
    match encoder.write_image(
        &canvas.into_raw(),
        image_size,
        image_size,
        image::ColorType::L8,
    ) {
        Ok(_) => Ok(vec),
        Err(err) => Err(err.to_string()),
    }
}

/// Draw text to a Base64-encoded PNG QR code.
///
/// # Errors
///
/// This will return an error in case the URL gets too long to encode into a QR code.
/// This would require the get_url method to generate an url bigger than 2000 characters,
/// Which would be too long for some browsers anyway.
///
/// It will also return an error in case it can't encode the qr into a png. This shouldn't happen unless either the qrcode library returns malformed data, or the image library doesn't encode the data correctly.
#[cfg(feature = "base64")]
pub fn draw_base64(text: &str) -> Result<String, String> {
    use base64::{engine::general_purpose, Engine as _};
    draw_png(text).map(|vec| general_purpose::STANDARD.encode(vec))
}
