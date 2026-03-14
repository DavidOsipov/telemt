#![allow(missing_docs)]

// Cryptobench
use aes::Aes256;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ctr::cipher::{KeyIvInit, StreamCipher};

type BenchAesCtr = ctr::Ctr128BE<Aes256>;

fn bench_aes_ctr(c: &mut Criterion) {
    c.bench_function("aes_ctr_encrypt_64kb", |b| {
        let data = vec![0u8; 65536];
        let key = [0u8; 32];
        let iv = [0u8; 16];
        b.iter(|| {
            let mut output = data.clone();
            let mut cipher = BenchAesCtr::new((&key).into(), (&iv).into());
            cipher.apply_keystream(&mut output);
            black_box(output)
        })
    });
}

criterion_group!(benches, bench_aes_ctr);
criterion_main!(benches);