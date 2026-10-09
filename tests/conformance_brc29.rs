//! The BRC-29 payment conformance vectors, run through the box's payment
//! path.
//!
//! `tests/vectors/brc29-payment-vectors.json` is a byte-pinned copy of the
//! canonical file, `conformance/brc29-payment-vectors.json` of the stack
//! review repository (bsv-stack-lean), which owns the vectors; its README
//! there gives the schema and the run recipe. Never edit the copy by hand: a
//! change starts in the canonical file and the copy follows, with
//! `VECTORS_SHA256` below (the same bytes bsv-middleware-rs 0.3.0 pins under
//! its own `tests/vectors/`). `the_vectors_are_the_pinned_bytes` holds the
//! copy to that digest wherever the tests run, and
//! `the_pinned_copy_is_the_canonical_file` compares it byte for byte with the
//! canonical file when that checkout is present (`BRC29_VECTORS_CANONICAL`,
//! else a sibling `bsv-stack-lean`), and says so when it is not.
//!
//! Every case goes where a `sendMessage` delivery payment goes: the
//! configured URL through `WorkerHeaderService::configured` (a `config` case
//! must name no service, and the verifier is then given none); the payment
//! through `delivery_verdict` as a wallet-payment remittance from the case's
//! sender, in each of the three shapes the route reads (a JSON byte array, a
//! hex string, `{"beef": <base64>}`), with the header service replaced by a
//! stub answering from `header_service.lookup`; the verdict through
//! `delivery_answer`, the route's answer. The verdict is mapped onto the
//! vector words and compared with `expected` exactly, 22 of 22, and the
//! route's status is held to the verdict's class (the canonical README, "The
//! six words": accept on `Verified` alone; `Underpaid`, `WrongScript` and
//! `RootMismatch` 4xx; `NoHeaderService` 5xx; `Unverifiable` by its reason's
//! side, the owner's ruling of 2026-10-09: a lookup error is the server's,
//! 5xx, and no root is the payer's, 4xx, with no fields).

use base64::Engine as _;
use bsv_middleware_rs::{HeaderLookupError, HeaderService, PaymentVerdict, UnverifiableReason};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use rust_message_box::payments::{delivery_answer, delivery_verdict, WorkerHeaderService};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

const VECTORS: &str = include_str!("vectors/brc29-payment-vectors.json");

/// The sha256 of the pinned copy (the canonical file's bytes).
const VECTORS_SHA256: &str = "836579ad73e20ca0e259a6c7cce5b55d85095cf290f74458937aeb39c9b5253c";

/// Where the canonical file is, when its checkout sits beside this one.
const CANONICAL_SIBLING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../bsv-stack-lean/conformance/brc29-payment-vectors.json"
);

/// What the box answered, as a vector word and its fields.
#[derive(Debug, Clone, PartialEq)]
struct Observed {
    word: String,
    fields: Value,
}

fn observed(word: &str, fields: Value) -> Observed {
    Observed {
        word: word.to_string(),
        fields,
    }
}

fn word(verdict: PaymentVerdict) -> Observed {
    match verdict {
        PaymentVerdict::Verified { satoshis } => {
            observed("Verified", json!({ "satoshis": satoshis }))
        }
        PaymentVerdict::Underpaid { paid, required } => {
            observed("Underpaid", json!({ "paid": paid, "required": required }))
        }
        PaymentVerdict::WrongScript { expected, actual } => observed(
            "WrongScript",
            json!({ "expected_script": hex::encode(expected), "actual_script": hex::encode(actual) }),
        ),
        PaymentVerdict::NoHeaderService => observed("NoHeaderService", json!({})),
        PaymentVerdict::RootMismatch {
            height,
            merkle_root,
        } => observed(
            "RootMismatch",
            json!({ "height": height, "merkle_root": merkle_root }),
        ),
        // The vectors give `Unverifiable` the height of the first root whose
        // lookup failed, and nothing else.
        PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed { height, .. }) => {
            observed("Unverifiable", json!({ "height": height }))
        }
        // No root (no proof, an incomplete BEEF) carries no fields: the
        // reason is the payer's side and the law does not name it.
        PaymentVerdict::Unverifiable(_) => observed("Unverifiable", json!({})),
    }
}

/// The reason of an `Unverifiable` verdict as the core names it, for the
/// run's printed line only: the vectors compare the word and the fields.
fn reason_of(verdict: &PaymentVerdict) -> Option<String> {
    match verdict {
        PaymentVerdict::Unverifiable(reason) => Some(format!("{:?}", reason)),
        _ => None,
    }
}

/// The status class the canonical README gives a verdict: 2 for the one
/// accept, 4 for a payment the payer must change, 5 for a payment the server
/// could not check. `Unverifiable` takes its reason's side: a lookup error
/// is the server's, no root is the payer's.
fn class_of(verdict: &PaymentVerdict) -> u16 {
    match verdict {
        PaymentVerdict::Verified { .. } => 2,
        PaymentVerdict::Underpaid { .. }
        | PaymentVerdict::WrongScript { .. }
        | PaymentVerdict::RootMismatch { .. } => 4,
        PaymentVerdict::NoHeaderService => 5,
        PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed { .. }) => 5,
        PaymentVerdict::Unverifiable(_) => 4,
    }
}

/// One case's answer from the box's path: the vector word and fields, the
/// route's status (200 for the one accept) and the core's reason.
#[derive(Debug, Clone, PartialEq)]
struct Answer {
    observed: Observed,
    status: u16,
    reason: Option<String>,
}

/// The header service of a case: `{"answer":"root","height":h,"merkle_root":r}`
/// answers `r` at `h` and nothing elsewhere; `{"answer":"error","reason":s}`
/// answers nothing; `null` is never asked. Records every height asked.
struct VectorHeaders {
    lookup: Value,
    asked: Mutex<Vec<u32>>,
}

#[async_trait::async_trait]
impl HeaderService for VectorHeaders {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.asked.lock().unwrap().push(height);
        match self.lookup["answer"].as_str() {
            Some("root") if self.lookup["height"].as_u64() == Some(u64::from(height)) => {
                Ok(self.lookup["merkle_root"].as_str().unwrap().to_string())
            }
            Some("root") => Err(HeaderLookupError(format!("no header at {}", height))),
            Some("error") => Err(HeaderLookupError(
                self.lookup["reason"].as_str().unwrap().to_string(),
            )),
            other => panic!("unknown lookup answer {:?}", other),
        }
    }
}

/// One case through the delivery check, in one shape of `tx`.
async fn run_shape(case: &Value, tx: &Value) -> Answer {
    let s = |k: &str| case[k].as_str().unwrap().to_string();
    let name = s("name");
    let wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(&s("server_private_key")).unwrap(),
    ));
    assert_eq!(
        wallet.identity_key().to_hex(),
        s("server_identity_key"),
        "{name}: server identity"
    );
    let sender = s("sender_identity_key");
    let remittance = json!({
        "outputIndex": case["output_index"],
        "protocol": "wallet payment",
        "paymentRemittance": {
            "derivationPrefix": s("derivation_prefix"),
            "derivationSuffix": s("derivation_suffix"),
            "senderIdentityKey": sender
        }
    });
    let price = case["required_satoshis"].as_u64().unwrap();
    let url = case["header_service"]["url"].as_str();
    let stage = s("stage");
    let headers = VectorHeaders {
        lookup: case["header_service"]["lookup"].clone(),
        asked: Mutex::new(Vec::new()),
    };
    let configured = WorkerHeaderService::configured(url).is_some();
    assert_eq!(
        configured,
        stage != "config",
        "{name}: whether the URL names a service"
    );
    let header_service = configured.then_some(&headers as &dyn HeaderService);
    let verdict = delivery_verdict(tx, &remittance, price, &sender, &wallet, header_service)
        .await
        .unwrap_or_else(|(body, status)| {
            panic!("{name}: refused before a verdict: {status} {body}")
        });
    let asked = headers.asked.lock().unwrap().clone();
    let got = word(verdict.clone());
    if stage == "output" && got.word != "Verified" {
        assert!(asked.is_empty(), "{name}: refused before any lookup");
    }
    if stage == "config" {
        assert!(asked.is_empty(), "{name}: no service, nothing asked");
    }
    if case["header_service"]["lookup"].is_null() {
        assert!(asked.is_empty(), "{name}: no root, nothing asked");
    }
    if case["requires_merkle_lookup"].as_bool().unwrap() {
        assert_eq!(
            asked,
            vec![case["transaction"]["proof"]["height"].as_u64().unwrap() as u32],
            "{name}: the proof's height is the one asked"
        );
    }
    let class = class_of(&verdict);
    let reason = reason_of(&verdict);
    // The route's answer to the verdict.
    let status = match delivery_answer(verdict) {
        Ok(satoshis) => {
            assert_eq!(class, 2, "{name}: accepted");
            assert_eq!(
                got.fields["satoshis"],
                json!(satoshis),
                "{name}: the amount"
            );
            200
        }
        Err((_, status)) => {
            assert_eq!(
                status / 100,
                class,
                "{name}: {} answered {status}",
                got.word
            );
            status
        }
    };
    Answer {
        observed: got,
        status,
        reason,
    }
}

/// One case in every shape the route reads; the shapes must agree.
async fn run_case(case: &Value) -> Answer {
    let name = case["name"].as_str().unwrap();
    let beef_hex = case["transaction"]["beef_hex"].as_str().unwrap();
    let bytes = hex::decode(beef_hex).unwrap();
    let got = run_shape(case, &json!(bytes)).await;
    for tx in [
        json!(beef_hex),
        json!({ "beef": base64::engine::general_purpose::STANDARD.encode(&bytes) }),
    ] {
        assert_eq!(run_shape(case, &tx).await, got, "{name}: every shape of tx");
    }
    got
}

#[test]
fn the_vectors_are_the_pinned_bytes() {
    assert_eq!(
        hex::encode(Sha256::digest(VECTORS.as_bytes())),
        VECTORS_SHA256,
        "tests/vectors/brc29-payment-vectors.json is stale or hand-edited: it is a copy of the \
         canonical file; copy that file again and update VECTORS_SHA256 in the same change"
    );
}

/// The copy is the canonical file, byte for byte. Where no checkout of the
/// canonical repository is present the digest above is the pin and this test
/// says that it compared nothing.
#[test]
fn the_pinned_copy_is_the_canonical_file() {
    let path =
        std::env::var("BRC29_VECTORS_CANONICAL").unwrap_or_else(|_| CANONICAL_SIBLING.to_string());
    match std::fs::read(&path) {
        Ok(canonical) => assert!(
            canonical == VECTORS.as_bytes(),
            "tests/vectors/brc29-payment-vectors.json differs from the canonical file {path}"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no canonical file at {path}; the copy is held by its sha256 alone");
        }
        Err(e) => panic!("cannot read {path}: {e}"),
    }
}

#[tokio::test]
async fn every_vector_case() {
    let file: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file["schema"], "brc29-payment-vectors/1");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    assert_eq!(
        file["words"].as_object().unwrap().len(),
        6,
        "six words in the glossary"
    );
    let mut failures = Vec::new();
    let mut exact = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = observed(
            case["expected"]["word"].as_str().unwrap(),
            case["expected"]["fields"].clone(),
        );
        let answer = run_case(case).await;
        let got = &answer.observed;
        // The ruling of 2026-10-09: `Unverifiable` with no fields is no
        // root, the payer's, and the route answers it 400.
        if expected.word == "Unverifiable" && expected.fields == json!({}) {
            assert_eq!(answer.status, 400, "{name}: no root is the payer's");
        }
        let verdict = if *got == expected {
            exact += 1;
            "ok"
        } else {
            failures.push(name.to_string());
            "FAIL"
        };
        let reason = answer.reason.map(|r| format!(" ({r})")).unwrap_or_default();
        println!(
            "{verdict:8} {name:40} expected {} {} got {} {} status {}{reason}",
            expected.word, expected.fields, got.word, got.fields, answer.status
        );
    }
    println!(
        "{exact} of {} exact, {} failing",
        cases.len(),
        failures.len()
    );
    assert!(failures.is_empty(), "failing cases: {:?}", failures);
    assert_eq!(exact, 22, "22 of 22 exact");
}
