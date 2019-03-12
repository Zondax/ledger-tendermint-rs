//! ledger-tendermint app benchmarks

#![allow(unused_imports)]
//#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate ledger_tendermint;

use criterion::Criterion;

fn pubkey_ed25519(c: &mut Criterion) {
    let app = ledger_tendermint::TendermintValidatorApp::connect().unwrap();

    c.bench_function("ledger-tm: Ed25519 get public key", move |b| {
        b.iter(|| app.public_key());
    });
}

fn get_fake_proposal(index: &mut u64, round: i64) -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};
    let other: [u8; 12] = [
        0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
    ];

    let mut message = Vec::new();

    message.write_u8(0x08).unwrap(); // (field_number << 3) | wire_type
    message.write_u8(0x01).unwrap(); // PrevoteType

    message.write_u8(0x11).unwrap(); // (field_number << 3) | wire_type
    message.write_u64::<LittleEndian>(*index).unwrap();

    message.write_u8(0x19).unwrap(); // (field_number << 3) | wire_type
    message.write_i64::<LittleEndian>(round).unwrap();

    // remaining fields (timestamp, not checked):
    message.write_u8(0x22).unwrap(); // (field_number << 3) | wire_type
    message.extend_from_slice(&other);

    // Increase index
    *index += 1;
    message
}

fn sign_votes(c: &mut Criterion) {
    let app = ledger_tendermint::TendermintValidatorApp::connect().unwrap();

    let mut index: u64 = 0;

    // initialize app with a vote
    let msg = get_fake_proposal(&mut index, 0);
    app.sign(&msg).unwrap();

    // Now measure
    c.bench_function("ledger-tm: Ed25519 sign votes", move |b| {
        b.iter(|| app.sign(&get_fake_proposal(&mut index, 0)).unwrap());
    });
}

criterion_group! {
    name = ed25519;
    config = Criterion::default();
//    targets = pubkey_ed25519, sign_votes
    targets = sign_votes
}

criterion_main!(ed25519);
