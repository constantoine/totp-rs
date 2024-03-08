use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn canvas_benchmark(c: &mut Criterion) {
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

fn png_benchmark(c: &mut Criterion) {
    let input = "otpauth://totp/GitHub:test?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=8&period=60&algorithm=SHA256";
    c.bench_with_input(
        BenchmarkId::new("qrcodegen-image", "draw_png"),
        black_box(&input),
        |b, i| {
            b.iter(|| {
                let _img = qrcodegen_image::draw_png(i);
            })
        },
    );
}

criterion_group!(benches, canvas_benchmark, png_benchmark);
criterion_main!(benches);
