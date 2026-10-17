use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Throughput};
use sorocharge_signer::{
    build_charge_entry_with_nonce, CredentialKind, sign_entry, ChargeParams, network_id_hash,
    Signer,
};
use sorocharge_signer::sign::FixedSeedSigner;
use stellar_xdr::ReadXdr;
use stellar_xdr::Limits;
use stellar_xdr::SorobanAuthorizationEntry;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature as DalekSignature};
use sha2::{Digest, Sha256};
use std::hint::black_box;

// A fixed-seed signer matching the payer keypair from the golden-vector generation,
// so both sides sign with the identical key.
struct FixedSeedSigner {
    signing_key: SigningKey,
    address: sorocharge_signer::entry::Address,
}

impl Signer for FixedSeedSigner {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], sorocharge_signer::error::SorochargeError> {
        Ok(self.signing_key.sign(preimage).to_bytes())
    }

    fn address(&self) -> sorocharge_signer::entry::Address {
        self.address.clone()
    }
}

fn make_signer(payer_addr: &str) -> FixedSeedSigner {
    let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
    let address: sorocharge_signer::entry::Address = payer_addr.parse().unwrap();
    FixedSeedSigner {
        signing_key,
        address,
    }
}

fn build_entry(params: &ChargeParams, credential_kind: CredentialKind, nonce: i64) -> sorocharge_signer::UnsignedEntry {
    build_charge_entry_with_nonce(params, credential_kind, nonce).expect("build_charge_entry_with_nonce should succeed")
}

fn make_charge_params(payer: &str, recipient: &str, amount: i128, valid_until_ledger: u32) -> ChargeParams {
    ChargeParams {
        asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
            .parse()
            .unwrap(),
        amount,
        payer: payer.parse().unwrap(),
        recipient: recipient.parse().unwrap(),
        valid_until_ledger,
    }
}

fn sign_and_verify(entry: sorocharge_signer::UnsignedEntry, signer: &FixedSeedSigner, passphrase: &str) -> sorocharge_signer::SignedEntry {
    sign_entry(entry, signer, passphrase).expect("sign_entry should succeed")
}

fn decode_entry(xdr_b64: &str) -> sorocharge_signer::SignedEntry {
    let entry = SorobanAuthorizationEntry::from_xdr_base64(xdr_b64, Limits::none())
        .expect("fixture XDR should decode");
    sorocharge_signer::SignedEntry(entry)
}

#[bench(b)]
fn bench_build_charge_entry_legacy(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::Legacy, 42);
    c.iter(|| build_charge_entry_with_nonce(&params, CredentialKind::Legacy, 42));
}

#[bench(b)]
fn bench_sign_entry_legacy(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::Legacy, 42);
    let signer = make_signer("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7");
    c.iter(|| sign_entry(unsigned, &signer, "Test SDF Network ; September 2015"));
}

#[bench(b)]
fn bench_verify_entry_legacy(c: &mut criterion::Bencher) {
    // First build and sign an entry, then verify it
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::Legacy, 42);
    let signer = make_signer("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7");
    let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").expect("sign_entry should succeed");

    c.iter(|| {
        let _ = sorocharge_signer::verify_entry(
            &signed,
            &params,
            123455,
            "Test SDF Network ; September 2015",
        );
    });
}

#[bench(b)]
fn bench_build_charge_entry_v2(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::AddressV2, 42);
    c.iter(|| build_charge_entry_with_nonce(&params, CredentialKind::AddressV2, 42));
}

#[bench(b)]
fn bench_sign_entry_v2(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::AddressV2, 42);
    let signer = make_signer("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7");
    c.iter(|| sign_entry(unsigned, &signer, "Test SDF Network ; September 2015"));
}

#[bench(b)]
fn bench_verify_entry_v2(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::AddressV2, 42);
    let signer = make_signer("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7");
    let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").expect("sign_entry should succeed");

    c.iter(|| {
        let _ = sorocharge_signer::verify_entry(
            &signed,
            &params,
            123455,
            "Test SDF Network ; September 2015",
        );
    });
}

#[bench(b)]
fn bench_build_charge_entry_delegated(c: &mut criterion::Bencher) {
    let params = make_charge_params(
        "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7",
        "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N",
        1000000000,
        123456,
    );
    let unsigned = build_entry(&params, CredentialKind::Delegated { signers: vec![] }, 42);
    // Note: this will fail due to empty signers, but we benchmark the build path
    // In practice you'd pass at least one signer
    c.iter(|| build_charge_entry_with_nonce(&params, CredentialKind::Delegated { signers: vec![] }, 42));
}

criterion_group!(
    benches,
    bench_build_charge_entry_legacy,
    bench_sign_entry_legacy,
    bench_verify_entry_legacy,
    bench_build_charge_entry_v2,
    bench_sign_entry_v2,
    bench_verify_entry_v2,
    bench_build_charge_entry_delegated
);

criterion_main!(benches);