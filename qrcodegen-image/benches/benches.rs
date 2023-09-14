use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let input = qrcodegen::QrCode::encode_text("otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256", qrcodegen::QrCodeEcc::Medium).unwrap();
    c.bench_with_input(
        BenchmarkId::new("qrcodegen-image", "draw_canvas"),
        black_box(&input),
        |b, i| {
            b.iter(|| {
                let _img = qrcodegen_image::draw_canvas(i.clone());
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
