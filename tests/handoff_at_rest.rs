//! NL-4b (the no-limits program, bsv-stack-lean `docs/charters/beef-of-any-size.md`):
//! a valid payment of any size is accepted end to end, not only at the door.
//!
//! 0.4.0's door (NL-4) gives a verdict that is free of size. What stood
//! behind it was not: after `Verified` the relay inlined the BEEF whole into
//! wallet-infra's JSON-RPC argument and into each paid recipient's D1 row, so
//! a large valid payment passed the door and failed there. Here the NL-4
//! witness's payment (100,000 unproven links under a proven parent, 6,200,112
//! bytes) goes through the door and through the hand-off:
//!
//! - the message is stored and the recipient lists it;
//! - the recipient's row holds the R2 key, the verdict and the subject's
//!   txid, and no byte of the BEEF;
//! - the BEEF is at rest in the object store, put there a chunk at a time;
//! - the delivery fee's internalize is deferred: a row of the ledger, and
//!   wallet-infra is handed nothing in the request.
//!
//! The rows are written by the route's own statements into a real SQLite
//! with the real migrations and D1's bound on a row (2,000,000 bytes: "D1's
//! 2 MB row", the charter's posture paragraph), so a row that carries the
//! BEEF fails here the way it fails in D1. The object store, wallet-infra and
//! the ledger are stand-ins behind the hand-off's seams. Every run is on a
//! thread with a 1 MiB stack, as in the NL-4 witness.

mod support;

use base64::Engine as _;
use rust_message_box::beef_door::{
    BeefStore, Chunks, Slice, Slices, Stamp, ROOT_LOOKUPS_PER_PASS, SCRIPT_INPUTS_PER_PASS,
    SCRIPT_WEIGHT_PER_PASS, VERIFY_SLICE_MILLIS,
};
use rust_message_box::handoff::{
    ack_delete_sql, ack_update_sql, drain_fees, forget_unnamed, hand_off, reclaim_released,
    stored_body, DeferredFee, Drained, Fee, FeeLedger, FeeWallet, HandedOff, Paid, PaymentStore,
    Reclaimed, RowRefs, Seams, FORGET_RELEASED_SQL, INSERT_MESSAGE_SQL, LIST_MESSAGES_SQL,
    READER_METADATA, RELEASED_KEYS_SQL, ROW_NAMES_KEY_SQL,
};
use rust_message_box::handoff::{health_figure, FeeFigure, FEE_ATTEMPTS_CEILING};
use rust_message_box::handoff::{
    orphaned, reask_announces, Announcer, Hint, OwedAnnounce, Reasked, Subject, CLAIMED_SQL,
    CLAIM_SQL, UNCLAIM_SQL,
};
use rust_message_box::handoff::{
    reclaim_minted, Expired, FORGET_MINTED_SQL, MINTED_DUE_SQL, MINTED_MARGIN_SECS, MINT_SQL,
    POSTPONE_MINTED_SQL,
};
use rust_message_box::payments::{
    judge_delivery_at_rest, judge_delivery_inline_at_rest, judge_delivery_output, Judged,
};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use support::*;

/// D1's bound on a string, a BLOB or a row.
const D1_ROW_BYTES: i32 = 2_000_000;

const RECIPIENT: &str = "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOW: u64 = 1_790_000_000;

// ---- the stand-ins behind the seams ----

/// The object store: objects with an etag, the door's states, and the
/// largest chunk a spool was handed.
#[derive(Default)]
struct Blobs {
    objects: RefCell<HashMap<String, (Vec<u8>, String)>>,
    states: RefCell<HashMap<String, Vec<u8>>>,
    largest_chunk: Cell<usize>,
    spools: Cell<usize>,
    /// How many times an object's bytes were opened.
    opened: Cell<usize>,
    /// The deployment names no bucket (`bucket_name`).
    nameless: Cell<bool>,
    /// Each object's custom metadata, as R2 keeps it beside the bytes.
    metadata: RefCell<HashMap<String, HashMap<String, String>>>,
}

struct Bytes {
    bytes: Vec<u8>,
    at: usize,
}

#[async_trait::async_trait(?Send)]
impl Chunks for Bytes {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let end = (self.at + 64 * 1024).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

#[async_trait::async_trait(?Send)]
impl BeefStore for Blobs {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        Ok(self.objects.borrow().get(key).map(|(bytes, etag)| Stamp {
            size: bytes.len() as u64,
            etag: etag.clone(),
        }))
    }

    async fn open(&self, key: &str, from: u64, stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        let objects = self.objects.borrow();
        let (bytes, etag) = objects.get(key).ok_or("no object")?;
        if *etag != stamp.etag {
            return Err("the object changed".to_string());
        }
        self.opened.set(self.opened.get() + 1);
        Ok(Box::new(Bytes {
            bytes: bytes[from as usize..].to_vec(),
            at: 0,
        }))
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.states.borrow().get(key).cloned())
    }

    async fn save(&self, key: &str, state: Vec<u8>) -> Result<(), String> {
        self.states.borrow_mut().insert(key.to_string(), state);
        Ok(())
    }

    async fn clear(&self, key: &str) -> Result<(), String> {
        self.states.borrow_mut().remove(key);
        self.objects.borrow_mut().remove(key);
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl PaymentStore for Blobs {
    async fn spool(
        &self,
        key: &str,
        chunks: &mut dyn Chunks,
        size: u64,
        reader: &str,
    ) -> Result<Stamp, String> {
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await? {
            self.largest_chunk
                .set(self.largest_chunk.get().max(chunk.len()));
            bytes.extend_from_slice(&chunk);
        }
        assert_eq!(bytes.len() as u64, size, "the spool is told the size");
        self.spools.set(self.spools.get() + 1);
        let etag = format!("spooled-{}", self.spools.get());
        self.objects
            .borrow_mut()
            .insert(key.to_string(), (bytes, etag.clone()));
        self.metadata.borrow_mut().insert(
            key.to_string(),
            HashMap::from([(READER_METADATA.to_string(), reader.to_string())]),
        );
        Ok(Stamp { size, etag })
    }

    async fn reader(&self, key: &str) -> Result<Option<String>, String> {
        let metadata = self.metadata.borrow();
        Ok(metadata
            .get(key)
            .and_then(|meta| meta.get(READER_METADATA))
            .cloned())
    }

    fn bucket_name(&self) -> Option<String> {
        (!self.nameless.get()).then(|| BUCKET.to_string())
    }
}

/// wallet-infra: accepts unless it is `down`, and keeps the bytes of every
/// `tx` it is handed, and each `internalizeAction` argument whole as the
/// relay's client sends it.
#[derive(Default)]
struct Wallet {
    handed: RefCell<Vec<usize>>,
    arguments: RefCell<Vec<Value>>,
    down: Cell<bool>,
}

#[async_trait::async_trait(?Send)]
impl FeeWallet for Wallet {
    async fn internalize(&self, args: &Value) -> Result<bool, String> {
        if self.down.get() {
            return Err("wallet-infra answered 502".to_string());
        }
        if let Some(tx) = args.get("tx") {
            self.handed.borrow_mut().push(tx.to_string().len());
        }
        self.arguments.borrow_mut().push(args.clone());
        Ok(true)
    }
}

/// The broadcaster: answers as scripted (a 200 unless told otherwise), and
/// counts what it is asked.
struct Broadcaster {
    answer: RefCell<Result<Hint, String>>,
    asked: Cell<usize>,
}

impl Default for Broadcaster {
    fn default() -> Self {
        Self {
            answer: RefCell::new(Ok(Hint {
                accepted: true,
                word: "ARC 200: SEEN_ON_NETWORK".to_string(),
            })),
            asked: Cell::new(0),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Announcer for Broadcaster {
    async fn announce(&self, _subject: Subject<'_>) -> Result<Hint, String> {
        self.asked.set(self.asked.get() + 1);
        self.answer.borrow().clone()
    }
}

/// The ledger of deferred fees, and of the announcements owed; each fee's
/// end, and the relay's word on wallet-infra's reach into the bucket.
#[derive(Default)]
struct Ledger {
    rows: RefCell<Vec<DeferredFee>>,
    announces: RefCell<Vec<(OwedAnnounce, String)>>,
    ended: RefCell<Vec<(String, String)>>,
    word: RefCell<Option<(String, u64)>>,
}

#[async_trait::async_trait(?Send)]
impl FeeLedger for Ledger {
    async fn defer(&self, fee: &DeferredFee) -> Result<(), String> {
        let mut rows = self.rows.borrow_mut();
        if !rows.iter().any(|row| row.key == fee.key) {
            rows.push(fee.clone());
        }
        Ok(())
    }
    async fn due(&self, now: u64, limit: u32) -> Result<Vec<DeferredFee>, String> {
        let rows = self.rows.borrow();
        let due = rows.iter().filter(|row| row.next_at <= now);
        Ok(due.take(limit as usize).cloned().collect())
    }
    async fn settle(&self, key: &str) -> Result<(), String> {
        self.rows.borrow_mut().retain(|row| row.key != key);
        Ok(())
    }
    async fn put_off(&self, key: &str, attempts: u32, next_at: u64, _: &str) -> Result<(), String> {
        for row in self.rows.borrow_mut().iter_mut().filter(|r| r.key == key) {
            row.attempts = attempts;
            row.next_at = next_at;
        }
        Ok(())
    }
    async fn owes(&self, key: &str) -> Result<bool, String> {
        Ok(self.rows.borrow().iter().any(|row| row.key == key)
            || self.announces.borrow().iter().any(|(a, _)| a.key == key))
    }
    async fn end(&self, key: &str, why: &str) -> Result<(), String> {
        self.rows.borrow_mut().retain(|row| row.key != key);
        self.ended
            .borrow_mut()
            .push((key.to_string(), why.to_string()));
        Ok(())
    }
    async fn figure(&self) -> Result<FeeFigure, String> {
        Ok(FeeFigure {
            owed: self.rows.borrow().len() as u64,
            ended: self.ended.borrow().len() as u64,
            last_ended: self.ended.borrow().last().map(|(_, why)| why.clone()),
        })
    }
    async fn wallet_word(&self) -> Result<Option<(String, u64)>, String> {
        Ok(self.word.borrow().clone())
    }
    async fn set_wallet_word(&self, word: Option<&str>, now: u64) -> Result<(), String> {
        *self.word.borrow_mut() = word.map(|w| (w.to_string(), now));
        Ok(())
    }
    async fn owe_announce(&self, owed: &OwedAnnounce, word: &str) -> Result<(), String> {
        let mut announces = self.announces.borrow_mut();
        if !announces.iter().any(|(a, _)| a.key == owed.key) {
            announces.push((owed.clone(), word.to_string()));
        }
        Ok(())
    }
    async fn due_announces(&self, now: u64, limit: u32) -> Result<Vec<OwedAnnounce>, String> {
        let announces = self.announces.borrow();
        let due = announces.iter().filter(|(a, _)| a.next_at <= now);
        Ok(due.take(limit as usize).map(|(a, _)| a.clone()).collect())
    }
    async fn announced(&self, key: &str) -> Result<(), String> {
        self.announces.borrow_mut().retain(|(a, _)| a.key != key);
        Ok(())
    }
    async fn put_off_announce(
        &self,
        key: &str,
        attempts: u32,
        next_at: u64,
        word: &str,
    ) -> Result<(), String> {
        for (a, last) in self
            .announces
            .borrow_mut()
            .iter_mut()
            .filter(|(a, _)| a.key == key)
        {
            a.attempts = attempts;
            a.next_at = next_at;
            *last = word.to_string();
        }
        Ok(())
    }
}

/// The stored rows as what names an object: the relay's own statements
/// (`storage::ROW_NAMES_KEY_SQL` and the release queue's) on the SQLite the
/// rows are in.
struct Rows<'a>(&'a rusqlite::Connection);

#[async_trait::async_trait(?Send)]
impl RowRefs for Rows<'_> {
    async fn names(&self, key: &str) -> Result<bool, String> {
        let mut statement = self.0.prepare(ROW_NAMES_KEY_SQL).unwrap();
        statement.exists([key]).map_err(|e| e.to_string())
    }
    async fn released(&self, limit: u32) -> Result<Vec<String>, String> {
        let mut statement = self.0.prepare(RELEASED_KEYS_SQL).unwrap();
        let keys = statement
            .query_map([limit], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>();
        keys.map_err(|e| e.to_string())
    }
    async fn forget(&self, key: &str) -> Result<(), String> {
        self.0
            .execute(FORGET_RELEASED_SQL, [key])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn claim(&self, key: &str) -> Result<(), String> {
        self.0
            .execute(CLAIM_SQL, [key])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn unclaim(&self, key: &str) -> Result<(), String> {
        self.0
            .execute(UNCLAIM_SQL, [key])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn claimed(&self, key: &str) -> Result<bool, String> {
        let mut statement = self.0.prepare(CLAIMED_SQL).unwrap();
        statement.exists([key]).map_err(|e| e.to_string())
    }
    async fn mint(&self, key: &str, deadline: u64) -> Result<(), String> {
        self.0
            .execute(MINT_SQL, rusqlite::params![key, deadline])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn minted_due(&self, now: u64, limit: u32) -> Result<Vec<String>, String> {
        let mut statement = self.0.prepare(MINTED_DUE_SQL).unwrap();
        let keys = statement
            .query_map(rusqlite::params![now, limit], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>();
        keys.map_err(|e| e.to_string())
    }
    async fn postpone_minted(&self, key: &str, deadline: u64) -> Result<(), String> {
        self.0
            .execute(POSTPONE_MINTED_SQL, rusqlite::params![deadline, key])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    async fn forget_minted(&self, key: &str) -> Result<(), String> {
        self.0
            .execute(FORGET_MINTED_SQL, [key])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// The relay's D1 schema on a real SQLite that refuses what D1 refuses of a
/// row, with the recipient's box made.
fn d1() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0002_transcript_retention.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0003_fee_internalize.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0004_beef_key.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0005_announce_owed.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0007_beef_reclaiming.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0008_beef_minted.sql"))
        .unwrap();
    db.execute_batch(include_str!("../migrations/0009_fee_terminal.sql"))
        .unwrap();
    db.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, D1_ROW_BYTES);
    db.execute(
        "INSERT INTO message_boxes (message_box_id, type, identity_key) VALUES (1, 'notifications', ?)",
        [RECIPIENT],
    )
    .unwrap();
    db
}

// ---- the payment ----

fn sender() -> String {
    wallet(SENDER_KEY).identity_key().to_hex()
}

/// The server's delivery output, with the sender's remittance.
fn delivery_output() -> Value {
    json!({
        "outputIndex": 0,
        "protocol": "wallet payment",
        "paymentRemittance": {
            "derivationPrefix": PREFIX,
            "derivationSuffix": SUFFIX,
            "senderIdentityKey": sender()
        }
    })
}

/// The recipient's output of the same payment.
fn recipient_output() -> Value {
    json!({
        "outputIndex": 1,
        "protocol": "wallet payment",
        "paymentRemittance": {
            "derivationPrefix": PREFIX,
            "derivationSuffix": SUFFIX,
            "senderIdentityKey": sender()
        }
    })
}

/// The subject's txid as it is displayed: the Atomic prefix carries it.
fn subject_txid(beef: &[u8]) -> String {
    hex::encode(beef[4..36].iter().rev().copied().collect::<Vec<u8>>())
}

fn headers(chain: &Chain) -> ChainHeaders {
    ChainHeaders {
        root: chain.root.clone(),
        asked: Arc::new(AtomicUsize::new(0)),
    }
}

/// The stand-ins and the database one or more sends share.
struct World {
    blobs: Blobs,
    wallet: Wallet,
    ledger: Ledger,
    arc: Broadcaster,
    db: rusqlite::Connection,
}

impl World {
    fn new() -> Self {
        Self {
            blobs: Blobs::default(),
            wallet: Wallet::default(),
            ledger: Ledger::default(),
            arc: Broadcaster::default(),
            db: d1(),
        }
    }

    /// The recipient's box as `/listMessages` reads it: id and body.
    fn listed(&self) -> Vec<(String, String)> {
        self.db
            .prepare(LIST_MESSAGES_SQL)
            .unwrap()
            .query_map(
                rusqlite::params![
                    RECIPIENT,
                    1,
                    100,
                    rust_message_box::handoff::LIST_INLINE_BYTES
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn has(&self, key: &str) -> bool {
        self.blobs.objects.borrow().contains_key(key)
    }
}

/// The hand-off's seams over a world.
macro_rules! seams {
    ($world:expr, $rows:ident) => {
        Seams {
            blobs: &$world.blobs,
            wallet: &$world.wallet,
            ledger: &$world.ledger,
            rows: &$rows,
            announcer: Some(&$world.arc),
        }
    };
}

/// What one send came to: the hand-off's result, the rows the recipient
/// lists, and the stand-ins as the send left them.
struct Sent {
    judged: Judged,
    handed: HandedOff,
    listed: Vec<(String, String)>,
    blobs: Blobs,
    wallet: Wallet,
    ledger: Ledger,
    arc: Broadcaster,
    db: rusqlite::Connection,
    spool_key: String,
}

/// A thread with a 1 MiB stack, as in the NL-4 witness.
fn on_a_small_stack<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .expect("the send returned")
}

fn block_on<T>(run: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(run)
}

/// One paid send, door to row, on a thread with a 1 MiB stack: the door's
/// verdict on `chain` (from R2 when `uploaded` names a key, from the request
/// otherwise), the hand-off, the recipient's row written and listed by the
/// route's statements. `rows` is whether the recipient is paid.
fn send(chain: Chain, uploaded: Option<&'static str>, rows: bool) -> Sent {
    send_with(chain, uploaded, rows, false)
}

/// `send`, with wallet-infra down for the request when `wallet_down`.
fn send_with(chain: Chain, uploaded: Option<&'static str>, rows: bool, wallet_down: bool) -> Sent {
    on_a_small_stack(move || {
        let world = World::new();
        world.wallet.down.set(wallet_down);
        let spool_key = format!("{}/5b0c1f6e2d3a4c7b8e9f0a1b2c3d4e5f.beef", sender());
        let (judged, handed) =
            block_on(send_into(&world, &chain, uploaded, rows, "m-1", &spool_key));
        let listed = world.listed();
        Sent {
            judged,
            handed,
            listed,
            blobs: world.blobs,
            wallet: world.wallet,
            ledger: world.ledger,
            arc: world.arc,
            db: world.db,
            spool_key,
        }
    })
}

/// One paid send into `world`: the door, the hand-off, and the recipient's
/// row `message_id` written by the route's statement, naming the object its
/// payment rests in.
async fn send_into(
    world: &World,
    chain: &Chain,
    uploaded: Option<&str>,
    rows: bool,
    message_id: &str,
    spool_key: &str,
) -> (Judged, HandedOff) {
    let sender = sender();
    let server_output = delivery_output();
    let headers = headers(chain);
    let payment = match uploaded {
        Some(key) => {
            // The sender's upload, once: a send naming the key again names
            // what is there. An upload carries no metadata of the relay's.
            if !world.has(key) {
                world
                    .blobs
                    .objects
                    .borrow_mut()
                    .insert(key.to_string(), (chain.beef.clone(), "uploaded".into()));
                world.blobs.metadata.borrow_mut().remove(key);
            }
            json!({
                "beefR2Key": key,
                "outputs": [server_output, recipient_output()],
                "description": "a paid message"
            })
        }
        None => json!({
            "tx": { "beef": base64::engine::general_purpose::STANDARD.encode(&chain.beef) },
            "outputs": [server_output, recipient_output()],
            "description": "a paid message"
        }),
    };

    // The door.
    let judged = match uploaded {
        Some(key) => {
            let clock = || 0u64;
            let slices = Slices {
                time: Slice {
                    clock: &clock,
                    millis: VERIFY_SLICE_MILLIS,
                },
                lookups: ROOT_LOOKUPS_PER_PASS,
                inputs: SCRIPT_INPUTS_PER_PASS,
                weight: SCRIPT_WEIGHT_PER_PASS,
            };
            judge_delivery_at_rest(
                &world.blobs,
                key,
                &server_output,
                FEE,
                &sender,
                &wallet(SERVER_KEY),
                Some(&headers),
                &slices,
            )
            .await
        }
        None => {
            judge_delivery_output(
                &payment["tx"],
                &server_output,
                FEE,
                &sender,
                &wallet(SERVER_KEY),
                Some(&headers),
            )
            .await
        }
    }
    .expect("the door verifies a valid payment of any size");

    // The hand-off.
    let stored_rows = Rows(&world.db);
    let handed = hand_off(
        &seams!(world, stored_rows),
        &Paid {
            payment: &payment,
            r2_key: uploaded,
            spooled: None,
            spool_key,
            server_output: Some(&server_output),
            stamp: judged.stamp.as_ref(),
            txid: Some(&judged.txid),
            rows,
            reader: &wallet(SERVER_KEY).identity_key().to_hex(),
            now: NOW,
        },
    )
    .await
    .expect("nothing after the verdict refuses the payment");

    // The recipient's row, by the route's statement.
    let message = json!("a message that was paid for");
    let body = stored_body(
        &message,
        rows.then_some((&handed.payment, &json!([recipient_output()]))),
    );
    let beef_key = rows.then(|| handed.payment["beefR2Key"].as_str()).flatten();
    let stored = world
        .db
        .execute(
            INSERT_MESSAGE_SQL,
            rusqlite::params![message_id, 1, sender, RECIPIENT, body, beef_key],
        )
        .expect("the recipient's row is stored");
    assert_eq!(stored, 1);
    (judged, handed)
}

/// The recipient's row as the witness reads it: one message, its payment
/// naming the object `key` and the subject, and no byte of the BEEF.
fn the_row_names_the_bytes_at_rest(sent: &Sent, beef: &[u8], key: &str) {
    assert_eq!(sent.listed.len(), 1, "the recipient lists the message");
    let (message_id, body) = &sent.listed[0];
    assert_eq!(message_id, "m-1");
    let row: Value = serde_json::from_str(body).unwrap();
    assert_eq!(row["message"], "a message that was paid for");
    let payment = &row["payment"];
    assert_eq!(payment["beefR2Key"], key, "the row carries the key");
    assert_eq!(payment["verdict"], "verified", "and the verdict");
    assert_eq!(
        payment["txid"],
        subject_txid(beef),
        "and the subject's txid"
    );
    assert_eq!(payment["beefSize"], beef.len());
    assert!(payment.get("tx").is_none(), "and never the BEEF");
    assert_eq!(payment["outputs"][0]["outputIndex"], 1, "with its outputs");
    assert!(
        body.len() < 2_048,
        "a row of {} bytes carries no BEEF",
        body.len()
    );
    assert_eq!(sent.handed.kept.as_deref(), Some(key));
    let objects = sent.blobs.objects.borrow();
    assert_eq!(objects[key].0, beef, "the BEEF is at rest, byte for byte");
}

#[test]
fn a_valid_payment_of_100_000_links_is_accepted_end_to_end() {
    let chain = chain_atomic_beef(100_000, 0);
    let beef = chain.beef.clone();
    println!("handoff_at_rest: 100000 links, {} bytes", beef.len());
    assert!(beef.len() > D1_ROW_BYTES as usize, "over D1's row");

    let sent = send(chain, None, true);

    assert_eq!(sent.judged.satoshis, FEE);
    assert_eq!(sent.judged.txid, subject_txid(&beef));
    the_row_names_the_bytes_at_rest(&sent, &beef, &sent.spool_key);
    assert!(
        sent.blobs.largest_chunk.get() <= 64 * 1024,
        "spooled a chunk at a time, never whole"
    );
    // The fee is owed, not refused: a row of the ledger, and wallet-infra
    // was handed nothing in the request.
    assert_eq!(sent.handed.fee, Fee::Deferred);
    assert!(sent.wallet.arguments.borrow().is_empty());
    let owed = sent.ledger.rows.borrow();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].key, sent.spool_key);
    assert_eq!(owed[0].txid, subject_txid(&beef));
    assert_eq!((owed[0].attempts, owed[0].next_at), (0, NOW));
    assert!(
        owed[0].args.len() < 1_024,
        "the ledger row carries no BEEF either"
    );
}

#[test]
fn the_same_payment_uploaded_to_r2_stays_where_it_arrived() {
    let chain = chain_atomic_beef(100_000, 0);
    let beef = chain.beef.clone();
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798/upload.beef";

    let sent = send(chain, Some(key), true);

    the_row_names_the_bytes_at_rest(&sent, &beef, key);
    // No second copy and no write (0.4.4, R403-M1): the one object as the
    // sender put it, and nothing at another key.
    assert_eq!(
        sent.blobs.spools.get(),
        0,
        "the object is never written again"
    );
    assert_eq!(sent.blobs.objects.borrow().len(), 1);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    assert!(sent.wallet.arguments.borrow().is_empty());
    let owed = sent.ledger.rows.borrow();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        (owed[0].key.as_str(), owed[0].etag.as_str()),
        (key, "uploaded"),
        "the etag the door verified"
    );
}

#[test]
fn an_everyday_payment_is_internalized_in_the_request_and_its_row_names_the_bytes_too() {
    let chain = chain_atomic_beef(10, 0);
    let beef = chain.beef.clone();

    let sent = send(chain, None, true);

    the_row_names_the_bytes_at_rest(&sent, &beef, &sent.spool_key);
    assert_eq!(sent.handed.fee, Fee::Internalized);
    assert_eq!(sent.wallet.handed.borrow().len(), 1, "wallet-infra, once");
    assert!(sent.ledger.rows.borrow().is_empty(), "nothing is owed");
    // The fee that fits is recorded inline, as `tx` in the one shape
    // wallet-infra decodes as it comes: the hex string (`[SRC] bsv-rs 0.4.1
    // src/wallet/types.rs:24-43`, `hex_bytes`; rust-wallet-infra@50a282f
    // src/beef_at_rest.rs:76-88 turns an array into it). The sender sent
    // `{"beef": <base64>}`, which wallet-infra refuses as a map.
    let arguments = sent.wallet.arguments.borrow();
    assert_eq!(arguments[0]["tx"], json!(hex::encode(&beef)), "tx as hex");
    assert!(arguments[0].get("beefAtRest").is_none());
}

#[test]
fn an_everyday_payment_uploaded_to_r2_is_recorded_in_the_request_as_hex() {
    let chain = chain_atomic_beef(10, 0);
    let beef = chain.beef.clone();

    let sent = send(chain, Some(UPLOADED), true);

    assert_eq!(sent.handed.fee, Fee::Internalized);
    let arguments = sent.wallet.arguments.borrow();
    assert_eq!(arguments.len(), 1, "wallet-infra, once");
    assert_eq!(arguments[0]["tx"], json!(hex::encode(&beef)), "tx as hex");
}

#[test]
fn a_payment_no_row_names_and_no_fee_waits_on_is_not_kept() {
    let sent = send(chain_atomic_beef(10, 0), None, false);

    assert_eq!(sent.handed.fee, Fee::Internalized);
    assert_eq!(sent.handed.kept, None);
    assert!(sent.blobs.objects.borrow().is_empty());
    let row: Value = serde_json::from_str(&sent.listed[0].1).unwrap();
    assert!(row.get("payment").is_none());
}

// ---- the reader on the object (NL-7b) ----
//
// wallet-infra honours a reference only for the caller the object's own
// metadata names (NL-7c, bsv-stack-lean `docs/lanes/nl-7c-at-rest-caller.md`:
// the custom metadata `recipient-identity-key`, read before the body). The
// one caller that hands wallet-infra a reference to the relay's objects is
// the relay's drain, signed in as the relay (`payments::internalize_server_fee`,
// `identityKey` the server's): the recipient of the delivery fee the
// reference is internalized for.

/// The relay's identity key: the recipient of the delivery fee.
fn relay() -> String {
    wallet(SERVER_KEY).identity_key().to_hex()
}

fn the_object_names_the_relay(sent: &Sent, key: &str, beef: &[u8]) {
    let metadata = sent.blobs.metadata.borrow();
    assert_eq!(
        metadata
            .get(key)
            .and_then(|meta| meta.get("recipient-identity-key")),
        Some(&relay()),
        "the object at {key} names the reader wallet-infra checks"
    );
    let objects = sent.blobs.objects.borrow();
    assert_eq!(
        objects[key].0, beef,
        "the bytes are the payment's, unchanged"
    );
    // The row and the deferred fee name the object as it is now.
    let etag = &objects[key].1;
    let row: Value = serde_json::from_str(&sent.listed[0].1).unwrap();
    assert_eq!(&row["payment"]["beefEtag"], etag);
    for fee in sent.ledger.rows.borrow().iter() {
        assert_eq!(&fee.etag, etag);
    }
}

#[test]
fn the_inline_paths_spool_names_the_relay_on_the_object() {
    let chain = chain_atomic_beef(100_000, 0);
    let beef = chain.beef.clone();
    let sent = send(chain, None, true);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    the_object_names_the_relay(&sent, &sent.spool_key, &beef);
}

/// An upload of an earlier release names no reader: since 0.4.4 its row
/// carries the reader beside the key, and the object is as the sender put
/// it (R403-M1). An upload minted by 0.4.4 names the relay itself (the
/// presigned PUT signs the header), and its row says nothing more.
#[test]
fn an_upload_that_names_no_reader_has_it_in_its_row_and_is_never_written_again() {
    let chain = chain_atomic_beef(100_000, 0);
    let sent = send(chain, Some(UPLOADED), true);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    assert_eq!(sent.blobs.spools.get(), 0);
    assert_eq!(sent.blobs.objects.borrow()[UPLOADED].1, "uploaded");
    assert!(sent.blobs.metadata.borrow().get(UPLOADED).is_none());
    let row: Value = serde_json::from_str(&sent.listed[0].1).unwrap();
    assert_eq!(row["payment"]["beefReader"], json!(relay()));
    assert_eq!(row["payment"]["beefEtag"], "uploaded");
    assert_eq!(sent.ledger.rows.borrow()[0].etag, "uploaded");

    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);
        world
            .blobs
            .objects
            .borrow_mut()
            .insert(UPLOADED.to_string(), (chain.beef.clone(), "minted".into()));
        world.blobs.metadata.borrow_mut().insert(
            UPLOADED.to_string(),
            HashMap::from([(READER_METADATA.to_string(), relay())]),
        );
        let (_, handed) = block_on(send_into(
            &world,
            &chain,
            Some(UPLOADED),
            true,
            "m-1",
            SPOOL,
        ));
        assert!(
            handed.payment.get("beefReader").is_none(),
            "the object names it"
        );
        assert_eq!(handed.payment["beefEtag"], "minted");
        assert_eq!(world.blobs.spools.get(), 0);
    });
}

#[test]
fn a_re_sent_key_is_never_written_again_and_both_rows_keep_its_etag() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);
        for message_id in ["m-1", "m-2"] {
            block_on(send_into(
                &world,
                &chain,
                Some(UPLOADED),
                true,
                message_id,
                SPOOL,
            ));
        }
        assert_eq!(world.blobs.spools.get(), 0, "never written");
        for (_, body) in world.listed() {
            let row: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(row["payment"]["beefEtag"], json!("uploaded"));
        }
    });
}

// ---- the deferred internalize and its drain ----

const UPLOADED: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798/upload.beef";

/// One drain at `now` over what a send left.
fn drain(sent: &Sent, now: u64) -> Drained {
    let rows = Rows(&sent.db);
    block_on(drain_fees(&seams!(sent, rows), now, 10)).expect("the drain ran")
}

/// The relay's bucket, as wallet-infra binds it (`BEEF_AT_REST_BUCKET`).
const BUCKET: &str = "bsv-messagebox-beefs";

/// `internalizeAction`'s argument names the bytes at rest and does not carry
/// them: `beefAtRest` with exactly the four fields wallet-infra reads
/// (`[SRC] rust-wallet-infra@50a282f src/beef_at_rest.rs:46-54`,
/// `deny_unknown_fields`), and no `tx` (both is refused, `:90-94`).
fn the_argument_is_the_reference(argument: &Value, key: &str, size: usize, etag: &str) {
    assert!(
        argument.get("tx").is_none(),
        "the drain sent `tx` (the inline argument, {} bytes), not the reference",
        argument["tx"].to_string().len()
    );
    assert_eq!(
        argument["beefAtRest"],
        json!({ "r2Key": key, "size": size, "etag": etag, "bucket": BUCKET }),
        "the reference: the ledger's key, the exact size, the etag unquoted, the bucket"
    );
    assert_eq!(argument["outputs"], json!([delivery_output()]));
    assert_eq!(argument["description"], "a paid message");
    assert_eq!(argument["seekPermission"], false);
}

#[test]
fn a_deferred_fee_of_100_000_links_is_sent_as_a_reference_and_recorded_on_the_next_drain() {
    let chain = chain_atomic_beef(100_000, 0);
    let beef = chain.beef.clone();
    let sent = send(chain, None, true);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    let etag = sent.ledger.rows.borrow()[0].etag.clone();

    let drained = drain(&sent, NOW);

    let arguments = sent.wallet.arguments.borrow();
    assert_eq!(arguments.len(), 1, "wallet-infra, once");
    the_argument_is_the_reference(&arguments[0], &sent.spool_key, beef.len(), &etag);
    assert_eq!(drained.settled, 1, "recorded on the next drain");
    assert!(sent.ledger.rows.borrow().is_empty(), "the row is cleared");
    // The recipient's row still names the bytes, so they stay.
    assert_eq!(sent.blobs.objects.borrow()[&sent.spool_key].0, beef);
    // And nothing is left to drain.
    drop(arguments);
    assert_eq!(drain(&sent, NOW + 86_400), Drained::default());
}

#[test]
fn a_fee_over_8_mib_is_sent_as_a_reference_too_and_is_never_held() {
    // One byte over what the drain at 0.4.1 handed wallet-infra in one argument.
    let chain = chain_of_exactly(10, 8 * 1024 * 1024 + 1);
    let size = chain.beef.len();

    let sent = send(chain, Some(UPLOADED), true);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    let etag = sent.ledger.rows.borrow()[0].etag.clone();

    let drained = drain(&sent, NOW);

    assert_eq!(drained.ended, 0, "a fee is never ended for its size");
    let arguments = sent.wallet.arguments.borrow();
    assert_eq!(arguments.len(), 1, "wallet-infra, once");
    the_argument_is_the_reference(&arguments[0], UPLOADED, size, &etag);
    assert_eq!(drained.settled, 1);
    assert!(sent.ledger.rows.borrow().is_empty());
}

#[test]
fn a_fault_in_wallet_infra_leaves_the_fee_owed_and_the_message_delivered() {
    let chain = chain_atomic_beef(10, 0);
    let beef = chain.beef.clone();

    // wallet-infra is down for the request: the send succeeds all the same.
    let sent = send_with(chain, None, true, true);

    the_row_names_the_bytes_at_rest(&sent, &beef, &sent.spool_key);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    assert_eq!(sent.ledger.rows.borrow().len(), 1);

    // Still down at the drain: the row stays, counted and put off.
    let first = drain(&sent, NOW);
    assert_eq!((first.settled, first.put_off), (0, 1));
    let (attempts, next_at) = {
        let rows = sent.ledger.rows.borrow();
        (rows[0].attempts, rows[0].next_at)
    };
    assert_eq!(attempts, 1);
    assert!(next_at > NOW, "retried later, with a backoff");
    // Not due before then.
    assert_eq!(drain(&sent, next_at - 1), Drained::default());
    // A second failure waits longer than the one before it.
    let second = drain(&sent, next_at);
    assert_eq!(second.put_off, 1);
    let later = sent.ledger.rows.borrow()[0].next_at;
    assert!(later - next_at > next_at - NOW, "the backoff grows");
    assert_eq!(sent.ledger.rows.borrow()[0].attempts, 2);

    // wallet-infra is back: the fee is recorded and the row cleared.
    sent.wallet.down.set(false);
    assert_eq!(drain(&sent, later).settled, 1);
    assert!(sent.ledger.rows.borrow().is_empty());
    let arguments = sent.wallet.arguments.borrow();
    assert_eq!(arguments.len(), 1, "wallet-infra answered once");
    assert!(arguments[0].get("beefAtRest").is_some(), "by reference");
}

#[test]
fn a_fee_no_row_names_keeps_its_bytes_until_it_is_recorded_and_no_longer() {
    let sent = send_with(chain_atomic_beef(10, 0), None, false, true);

    // No row names the payment, and the fee waits on its bytes.
    assert_eq!(sent.handed.fee, Fee::Deferred);
    assert_eq!(sent.handed.kept.as_deref(), Some(sent.spool_key.as_str()));
    assert_eq!(sent.blobs.objects.borrow().len(), 1);

    sent.wallet.down.set(false);
    assert_eq!(drain(&sent, NOW).settled, 1);
    assert!(
        sent.blobs.objects.borrow().is_empty(),
        "nothing names them now"
    );
}

#[test]
fn a_fee_is_never_recorded_from_another_upload_at_its_key() {
    let sent = send_with(chain_atomic_beef(10, 0), Some(UPLOADED), true, true);
    assert_eq!(sent.handed.fee, Fee::Deferred);
    sent.wallet.down.set(false);

    // The sender's presigned URL is still good: other bytes at the key.
    sent.blobs
        .objects
        .borrow_mut()
        .insert(UPLOADED.to_string(), (vec![0u8; 64], "another".into()));

    assert_eq!(drain(&sent, NOW).ended, 1);
    assert!(sent.wallet.arguments.borrow().is_empty());
    // 0.4.4 (R403-L1): the fee ends with its reason; 0.4.3 kept it owed and
    // retried it daily without end.
    assert!(sent.ledger.rows.borrow().is_empty());
    assert_eq!(
        sent.ledger.ended.borrow()[0],
        (
            UPLOADED.to_string(),
            "another upload is at the key".to_string()
        )
    );
}

// ---- ownership: an object is deleted only when no stored row names it (NL-4c) ----
//
// The bytes of a paid message rest in R2 under the sender's key space, and a
// recipient's row names them. Until NL-4c the relay deleted an object by what
// one send knew of it: a later send naming the same key, with no row and no
// fee of its own, deleted an object an earlier send's row still named; and
// nothing ever deleted the object of an acknowledged message. Here the rows
// are in a real SQLite with the real migrations, written, acknowledged and
// retired by the route's own statements, and the object store is asked what
// is left.

const SPOOL: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798/spooled.beef";

/// The recipient acknowledges `message_id` in a box that is not retained:
/// the route's delete (`retention::ack_delete_sql`, retention off).
fn acknowledge(world: &World, message_id: &str) {
    let deleted = world
        .db
        .execute(&ack_delete_sql(1, 0), [RECIPIENT, message_id])
        .unwrap();
    assert_eq!(deleted, 1, "the row is acknowledged");
}

/// The recipient acknowledges `message_id` in a retained box: the route's
/// mark (`retention::ack_update_sql`), the row staying for the transcript.
fn retire(world: &World, message_id: &str) {
    let marked = world
        .db
        .execute(
            &ack_update_sql(1, 1),
            [RECIPIENT, message_id, "notifications%"],
        )
        .unwrap();
    assert_eq!(marked, 1, "the row is marked delivered");
    assert_eq!(world.listed().len(), 0, "and no longer listed");
}

/// One pass of the scheduled reclaim over what the rows have let go of.
fn reclaim_pass(world: &World) -> Reclaimed {
    let rows = Rows(&world.db);
    block_on(reclaim_released(&seams!(world, rows), 10)).expect("the pass ran")
}

fn released(world: &World) -> Vec<String> {
    block_on(Rows(&world.db).released(10)).unwrap()
}

#[test]
fn a_re_sent_key_cannot_delete_an_object_a_stored_row_still_names() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);

        // The earlier send: the recipient is paid, and its row names the upload.
        let (_, earlier) = block_on(send_into(
            &world,
            &chain,
            Some(UPLOADED),
            true,
            "m-1",
            SPOOL,
        ));
        assert_eq!(earlier.kept.as_deref(), Some(UPLOADED));
        assert_eq!(world.listed().len(), 1);

        // The sender names the same key again, in a send no row and no fee
        // of its own will name (the fee is recorded in the request).
        let (_, second) = block_on(send_into(
            &world,
            &chain,
            Some(UPLOADED),
            false,
            "m-2",
            SPOOL,
        ));
        assert_eq!((second.fee, second.kept.clone()), (Fee::Internalized, None));
        let rows = Rows(&world.db);
        let deleted = block_on(forget_unnamed(
            &seams!(world, rows),
            0,
            &second,
            Some(UPLOADED),
            false,
        ));

        assert!(!deleted, "the earlier send's row still names the object");
        assert!(world.has(UPLOADED), "the object is where the row says");
        assert_eq!(world.blobs.objects.borrow()[UPLOADED].0, chain.beef);
    });
}

#[test]
fn a_fee_recorded_for_a_re_sent_key_cannot_delete_the_object_either() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);
        block_on(send_into(
            &world,
            &chain,
            Some(UPLOADED),
            true,
            "m-1",
            SPOOL,
        ));

        // The same key again, no row of its own, and wallet-infra down: the
        // fee is deferred, recorded as one no row names.
        world.wallet.down.set(true);
        let (_, second) = block_on(send_into(
            &world,
            &chain,
            Some(UPLOADED),
            false,
            "m-2",
            SPOOL,
        ));
        assert_eq!(second.fee, Fee::Deferred);
        assert!(!world.ledger.rows.borrow()[0].named);

        // The drain records the fee. The earlier send's row still names the
        // object, whatever the fee's own row said.
        world.wallet.down.set(false);
        let rows = Rows(&world.db);
        let drained = block_on(drain_fees(&seams!(world, rows), NOW, 10)).unwrap();
        assert_eq!(drained.settled, 1);
        assert!(world.ledger.rows.borrow().is_empty());
        assert!(world.has(UPLOADED), "the object is where the row says");
    });
}

#[test]
fn an_acknowledged_messages_object_is_reclaimed_once_no_row_names_it() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);

        // One payment, two rows naming its object (two paid recipients'
        // rows are one object).
        block_on(send_into(&world, &chain, None, true, "m-1", SPOOL));
        let (id, body): (String, String) = world.listed().remove(0);
        world
            .db
            .execute(
                INSERT_MESSAGE_SQL,
                rusqlite::params!["m-2", 1, sender(), RECIPIENT, body, SPOOL],
            )
            .unwrap();
        assert_eq!(id, "m-1");
        assert!(world.has(SPOOL));
        assert!(released(&world).is_empty(), "nothing is let go of yet");
        assert_eq!(reclaim_pass(&world), Reclaimed::default());

        // One row is acknowledged: its key is released, and the other
        // row still names the object.
        acknowledge(&world, "m-1");
        assert_eq!(released(&world), [SPOOL]);
        assert_eq!(
            reclaim_pass(&world),
            Reclaimed {
                deleted: 0,
                named: 1,
                put_off: 0
            }
        );
        assert!(world.has(SPOOL), "a stored row names it");
        assert!(released(&world).is_empty(), "the key was looked at");

        // The last row is acknowledged: nothing names the object, and it is
        // reclaimed.
        acknowledge(&world, "m-2");
        assert_eq!(
            reclaim_pass(&world),
            Reclaimed {
                deleted: 1,
                named: 0,
                put_off: 0
            }
        );
        assert!(!world.has(SPOOL), "reclaimed");
        assert_eq!(reclaim_pass(&world), Reclaimed::default());
    });
}

#[test]
fn a_retired_message_lets_go_of_its_object_and_a_fee_still_owed_keeps_it() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(10, 0);

        // wallet-infra is down: the row names the object and so does the
        // deferred fee.
        world.wallet.down.set(true);
        let (_, handed) = block_on(send_into(&world, &chain, None, true, "m-1", SPOOL));
        assert_eq!(handed.fee, Fee::Deferred);

        // The row is retired (acknowledged in a retained box: it stays, and
        // no longer names the object). The fee still does.
        retire(&world, "m-1");
        assert_eq!(released(&world), [SPOOL]);
        assert_eq!(reclaim_pass(&world).named, 1);
        assert!(world.has(SPOOL), "the fee is owed on these bytes");

        // The fee is recorded: nothing names the object, and it goes with
        // the fee.
        world.wallet.down.set(false);
        let rows = Rows(&world.db);
        let drained = block_on(drain_fees(&seams!(world, rows), NOW, 10)).unwrap();
        assert_eq!(drained.settled, 1);
        assert!(!world.has(SPOOL), "reclaimed with the fee");
    });
}

// ---- the inline payment spooled before its scripts (0.4.4, bsv-low #591 H1) ----
//
// Through 0.4.3 an inline payment was read in one pass in the request, the
// scripts with it, and had no slice: a wide body was one reading of all its
// CPU (LOW's 18.5 to 186 s). Since 0.4.4 its structure and its paying output
// are read in the request, and a payment that pays is spooled before its
// scripts run and read from rest in slices, as an upload is.

/// What the spooled door came to: the verdict, the key, the pending phases.
type Spooled = (Result<Judged, (Value, u16)>, Option<String>, Vec<String>);

/// The door on an inline `tx` through the spool, every request sent again
/// until a verdict, with a clock that moves one millisecond a reading of it
/// and a slice of one: each request reads about one element. The verdict,
/// the key, and the pending answers' phases.
fn inline_in_slices(world: &World, tx: &Value, chain: &Chain, fee: u64) -> Spooled {
    let headers = headers(chain);
    let ticks = Cell::new(0u64);
    let clock = || {
        ticks.set(ticks.get() + 1);
        ticks.get()
    };
    let slices = Slices {
        time: Slice {
            clock: &clock,
            millis: 1,
        },
        lookups: usize::MAX,
        inputs: u64::MAX,
        weight: u64::MAX,
    };
    let mut phases = Vec::new();
    loop {
        let (judged, key) = block_on(judge_delivery_inline_at_rest(
            &world.blobs,
            tx,
            &delivery_output(),
            fee,
            &sender(),
            &wallet(SERVER_KEY),
            Some(&headers),
            &slices,
            &relay(),
            None,
        ));
        match &judged {
            Err((body, 503)) if body["code"] == "ERR_PAYMENT_PENDING" => {
                phases.push(body["phase"].as_str().unwrap().to_string());
                assert!(phases.len() < 10_000, "the requests end");
            }
            _ => return (judged, key, phases),
        }
    }
}

#[test]
fn an_inline_payment_that_pauses_at_the_slice_resumes_to_the_same_verdict() {
    on_a_small_stack(|| {
        let chain = chain_atomic_beef(300, 0);
        let tx = json!({ "beef": base64::engine::general_purpose::STANDARD.encode(&chain.beef) });
        // The verdict of one request, in the request (no bucket).
        let headers = headers(&chain);
        let whole = block_on(judge_delivery_output(
            &tx,
            &delivery_output(),
            FEE,
            &sender(),
            &wallet(SERVER_KEY),
            Some(&headers),
        ))
        .expect("the payment is valid");

        let world = World::new();
        let (judged, key, phases) = inline_in_slices(&world, &tx, &chain, FEE);
        let key = key.expect("the bytes were put at rest");
        let count = |phase: &str| phases.iter().filter(|p| *p == phase).count();
        eprintln!(
            "handoff_at_rest: inline, {} bytes: {} pending ({} structure, {} scripts, {} roots)",
            chain.beef.len(),
            phases.len(),
            count("structure"),
            count("scripts"),
            count("roots")
        );
        let judged = judged.expect("the verdict");
        assert_eq!(
            (judged.satoshis, &judged.txid),
            (whole.satoshis, &whole.txid),
            "the verdict of one request"
        );
        assert_eq!(
            judged.stamp.as_ref().map(|s| s.size),
            Some(chain.beef.len() as u64)
        );
        assert!(phases.len() > 100, "{} requests paused", phases.len());
        assert!(
            phases.iter().any(|p| p == "scripts"),
            "it paused in the scripts"
        );
        assert!(key.starts_with(&format!("{}/inline-", sender())), "{key}");
        assert_eq!(
            world.blobs.spools.get(),
            1,
            "spooled once, found again by every retry"
        );
        assert_eq!(world.blobs.objects.borrow()[&key].0, chain.beef);
        assert!(
            world.blobs.states.borrow().is_empty(),
            "a verdict leaves no state"
        );
        assert_eq!(
            world.blobs.metadata.borrow()[&key].get(READER_METADATA),
            Some(&relay()),
            "the spool names the relay as its reader"
        );

        // The hand-off keeps the bytes where the door read them.
        let stored_rows = Rows(&world.db);
        let payment = json!({
            "tx": tx,
            "outputs": [delivery_output(), recipient_output()],
        });
        let handed = block_on(hand_off(
            &seams!(world, stored_rows),
            &Paid {
                payment: &payment,
                r2_key: None,
                spooled: Some(&key),
                spool_key: "unused",
                server_output: Some(&delivery_output()),
                stamp: None,
                txid: Some(&whole.txid),
                rows: true,
                reader: &relay(),
                now: NOW,
            },
        ))
        .expect("handed off");
        assert_eq!(handed.kept.as_deref(), Some(key.as_str()));
        assert_eq!(handed.payment["beefR2Key"], key);
        assert_eq!(handed.payment["txShape"], "base64");
        assert_eq!(world.blobs.spools.get(), 1, "never spooled again");
    });
}

#[test]
fn an_inline_payment_that_pays_too_little_is_refused_in_the_request_and_nothing_is_put_at_rest() {
    on_a_small_stack(|| {
        let chain = chain_atomic_beef(300, 0);
        let tx = json!(hex::encode(&chain.beef));
        let world = World::new();
        let (judged, key, phases) = inline_in_slices(&world, &tx, &chain, FEE + 1);
        let (body, status) = judged.expect_err("an underpayment");
        assert_eq!(
            (status, &body["code"]),
            (400, &json!("ERR_INSUFFICIENT_PAYMENT"))
        );
        assert_eq!((key, phases.len()), (None, 0));
        assert_eq!(world.blobs.spools.get(), 0, "nothing spooled");
    });
}

// ---- the subject announced before delivery (0.4.4, bsv-low #591 M2) ----
//
// Through 0.4.3 nothing in the relay posted the subject: a deferred fee was
// credit until a drain, and the drain hands wallet-infra a reference, which
// broadcasts nothing either. Since 0.4.4 the relay announces the subject in
// the send; the broadcaster's word is a hint (bsv-stack-lean
// `docs/charters/tracker.md` section 2): the message is delivered on the
// door's verdict whatever it says, the row keeps the word, and a word that is
// not an acceptance is owed and asked again by the drain.

fn refusing(world: &World) {
    *world.arc.answer.borrow_mut() = Ok(Hint {
        accepted: false,
        word: "ARC 503: Service Unavailable".to_string(),
    });
}

#[test]
fn a_paid_send_whose_broadcaster_answers_a_5xx_is_delivered_its_row_carries_the_hint_and_the_drain_re_asks(
) {
    on_a_small_stack(|| {
        let world = World::new();
        refusing(&world);
        let chain = chain_atomic_beef(3, 0);
        let spool_key = format!("{}/5b0c1f6e2d3a4c7b8e9f0a1b2c3d4e5f.beef", sender());
        let (_, handed) = block_on(send_into(&world, &chain, None, true, "m-1", &spool_key));

        // Delivered, the fee recorded, the word on the row.
        let listed = world.listed();
        assert_eq!(listed.len(), 1, "the message is delivered");
        let row: Value = serde_json::from_str(&listed[0].1).unwrap();
        assert_eq!(
            row["payment"]["announced"],
            json!({ "accepted": false, "word": "ARC 503: Service Unavailable" })
        );
        assert_eq!(
            row["payment"]["verdict"], "verified",
            "the door's verdict stands"
        );
        assert_eq!(handed.fee, Fee::Internalized);
        assert_eq!(world.arc.asked.get(), 1, "announced in the send");

        // Owed, naming the bytes at rest.
        let owed = world.ledger.announces.borrow().clone();
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].0.key, spool_key);
        assert_eq!(owed[0].0.txid, subject_txid(&chain.beef));
        assert_eq!(owed[0].1, "ARC 503: Service Unavailable");

        // The drain asks again: still refused, put off with one more attempt.
        let stored_rows = Rows(&world.db);
        let seams = seams!(world, stored_rows);
        assert_eq!(
            block_on(reask_announces(&seams, NOW, 10)).unwrap(),
            Reasked {
                accepted: 0,
                put_off: 1
            }
        );
        assert_eq!(world.arc.asked.get(), 2);
        assert_eq!(world.ledger.announces.borrow()[0].0.attempts, 1);
        assert!(world.ledger.announces.borrow()[0].0.next_at > NOW);

        // Taken on a later pass: the debt is gone; the row still names the
        // bytes, so they stay.
        *world.arc.answer.borrow_mut() = Ok(Hint {
            accepted: true,
            word: "ARC 200: SEEN_ON_NETWORK".to_string(),
        });
        assert_eq!(
            block_on(reask_announces(&seams, NOW + 86_400, 10)).unwrap(),
            Reasked {
                accepted: 1,
                put_off: 0
            }
        );
        assert!(world.ledger.announces.borrow().is_empty());
        assert!(world.has(&spool_key), "the row names the bytes");
    });
}

#[test]
fn an_announcement_owed_keeps_its_bytes_when_no_row_names_them_and_lets_go_once_taken() {
    on_a_small_stack(|| {
        let world = World::new();
        *world.arc.answer.borrow_mut() = Err("connection reset".to_string());
        let chain = chain_atomic_beef(3, 0);
        let spool_key = format!("{}/5b0c1f6e2d3a4c7b8e9f0a1b2c3d4e5f.beef", sender());
        let (_, handed) = block_on(send_into(&world, &chain, None, false, "m-1", &spool_key));
        assert_eq!(
            handed.kept.as_deref(),
            Some(spool_key.as_str()),
            "kept for the re-ask"
        );
        assert_eq!(
            handed.hint,
            Some(Hint {
                accepted: false,
                word: "no answer: connection reset".to_string()
            })
        );
        assert!(world.has(&spool_key));
        *world.arc.answer.borrow_mut() = Ok(Hint {
            accepted: true,
            word: "ARC 200: SEEN_ON_NETWORK".to_string(),
        });
        let stored_rows = Rows(&world.db);
        let reasked = block_on(reask_announces(&seams!(world, stored_rows), NOW, 10)).unwrap();
        assert_eq!(reasked.accepted, 1);
        assert!(!world.has(&spool_key), "nothing names the bytes now");
    });
}

// ---- NOTE-3: a box of rows near D1's bound lists within the budget ----

/// bsv-low #591 NOTE-3: the list statement read up to 100 rows whole, and a
/// row is up to D1's 2,000,000 bytes, so one listing could hand the isolate
/// about 200 MB before any budget ran. Since 0.4.4 the statement itself
/// stops at the response's budget (`handoff::LIST_INLINE_BYTES`, about 16
/// MB of stored text): twenty rows of 1,900,000 bytes list eight at a time,
/// and the rest are in the next listing.
#[test]
fn a_box_of_two_megabyte_rows_lists_within_the_budget() {
    let world = World::new();
    let message = "a".repeat(1_900_000 - 20);
    for i in 0..20 {
        let body = json!({ "message": message }).to_string();
        world
            .db
            .execute(
                INSERT_MESSAGE_SQL,
                rusqlite::params![
                    format!("m-{i}"),
                    1,
                    sender(),
                    RECIPIENT,
                    body,
                    None::<String>
                ],
            )
            .expect("a row under D1's bound");
    }
    let listed = world.listed();
    let text: usize = listed.iter().map(|(_, body)| body.len()).sum();
    eprintln!(
        "handoff_at_rest: a box of 20 rows of 1.9 MB lists {} rows, {} bytes",
        listed.len(),
        text
    );
    assert!(
        text as u64 <= rust_message_box::handoff::LIST_INLINE_BYTES,
        "{text} bytes in one listing"
    );
    assert_eq!(listed.len(), 8);
    assert_eq!(listed[0].0, "m-0", "the order is the box's");
}

// ---- L1: the door's stamp carried into the hand-off ----

/// bsv-low #591 L1: through 0.4.3 the hand-off stamped the key afresh, so
/// bytes put at the key between the verdict and the hand-off were the ones
/// named, recorded `verified` and handed on. Since 0.4.4 the verdict carries
/// the stamp of what the door read, and the hand-off records nothing of other
/// bytes: 503 `ERR_PAYMENT_CHANGED`, nothing in a row, no fee owed, no
/// announcement; the same request again reads the object as it is.
#[test]
fn bytes_replaced_between_the_verdict_and_the_hand_off_are_never_recorded_verified() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(3, 0);
        let key = format!("{}/upload.beef", sender());
        world
            .blobs
            .objects
            .borrow_mut()
            .insert(key.clone(), (chain.beef.clone(), "uploaded".into()));
        let headers = headers(&chain);
        let clock = || 0u64;
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis: VERIFY_SLICE_MILLIS,
            },
            lookups: ROOT_LOOKUPS_PER_PASS,
            inputs: SCRIPT_INPUTS_PER_PASS,
            weight: SCRIPT_WEIGHT_PER_PASS,
        };
        let judged = block_on(judge_delivery_at_rest(
            &world.blobs,
            &key,
            &delivery_output(),
            FEE,
            &sender(),
            &wallet(SERVER_KEY),
            Some(&headers),
            &slices,
        ))
        .expect("the door verifies the upload");
        assert_eq!(
            judged.stamp.as_ref().map(|s| s.etag.as_str()),
            Some("uploaded")
        );

        // Another upload at the key, after the verdict.
        let other = chain_atomic_beef(4, 0).beef;
        world
            .blobs
            .objects
            .borrow_mut()
            .insert(key.clone(), (other, "replaced".into()));

        let payment = json!({
            "beefR2Key": key,
            "outputs": [delivery_output(), recipient_output()],
        });
        let stored_rows = Rows(&world.db);
        let (body, status) = block_on(hand_off(
            &seams!(world, stored_rows),
            &Paid {
                payment: &payment,
                r2_key: Some(&key),
                spooled: None,
                spool_key: "unused",
                server_output: Some(&delivery_output()),
                stamp: judged.stamp.as_ref(),
                txid: Some(&judged.txid),
                rows: true,
                reader: &relay(),
                now: NOW,
            },
        ))
        .expect_err("nothing of other bytes is recorded");
        eprintln!("handoff_at_rest: {status} {}", body["description"]);
        assert_eq!(
            (status, &body["code"]),
            (503, &json!("ERR_PAYMENT_CHANGED"))
        );
        assert!(world.ledger.rows.borrow().is_empty(), "no fee owed");
        assert!(
            world.ledger.announces.borrow().is_empty(),
            "nothing announced"
        );
        assert_eq!(world.arc.asked.get(), 0);
        assert!(
            world.wallet.arguments.borrow().is_empty(),
            "wallet-infra asked nothing"
        );
    });
}

// ---- L2: the claim, on the relay's own statements ----

/// bsv-low #591 L2, the send's side: a send writes its row and then reads
/// the claim. While a reclaim holds the key the claim is seen; were the bytes
/// gone, the row is an orphan and the route logs it with its key. A claim
/// let go of, or one older than five minutes, is no claim.
#[test]
fn a_send_that_names_a_key_a_reclaim_holds_sees_the_claim_and_an_orphan_is_named() {
    on_a_small_stack(|| {
        let world = World::new();
        let rows = Rows(&world.db);
        let seams = seams!(world, rows);
        let key = format!("{}/upload.beef", sender());
        world
            .blobs
            .objects
            .borrow_mut()
            .insert(key.clone(), (vec![1, 2, 3], "uploaded".into()));
        // No claim: nothing to say, the bytes or not.
        assert!(!block_on(orphaned(&seams, &key)));
        block_on(RowRefs::claim(&rows, &key)).unwrap();
        assert!(block_on(RowRefs::claimed(&rows, &key)).unwrap());
        assert!(
            !block_on(orphaned(&seams, &key)),
            "the bytes are still there"
        );
        world.blobs.objects.borrow_mut().remove(&key);
        assert!(
            block_on(orphaned(&seams, &key)),
            "an orphan, named by its key"
        );
        block_on(RowRefs::unclaim(&rows, &key)).unwrap();
        assert!(!block_on(orphaned(&seams, &key)), "the claim is let go of");
        // A stale claim is no claim.
        world
            .db
            .execute(
                "INSERT INTO beef_reclaiming (key, claimed_at) VALUES (?, 1)",
                [&key],
            )
            .unwrap();
        assert!(!block_on(RowRefs::claimed(&rows, &key)).unwrap());
    });
}

/// And the reclaim's side on the same statements: a reclaim that finds the
/// key named by a row deletes nothing and lets go of its claim.
#[test]
fn a_reclaim_lets_go_of_its_claim_whatever_it_finds() {
    on_a_small_stack(|| {
        let world = World::new();
        let chain = chain_atomic_beef(3, 0);
        let spool_key = format!("{}/5b0c1f6e2d3a4c7b8e9f0a1b2c3d4e5f.beef", sender());
        block_on(send_into(&world, &chain, None, true, "m-1", &spool_key));
        let rows = Rows(&world.db);
        let seams = seams!(world, rows);
        assert_eq!(
            block_on(rust_message_box::handoff::reclaim(&seams, &spool_key)),
            Ok(false)
        );
        assert!(world.has(&spool_key));
        assert!(!block_on(RowRefs::claimed(&rows, &spool_key)).unwrap());
    });
}

// ---- L3: an object nobody names is reclaimed by its deadline ----

/// bsv-low #591 L3: through 0.4.3 an object no send named (an upload URL
/// minted and used, then never sent) was never looked at again. Since 0.4.4
/// every key the relay mints is recorded with a deadline (the URL's life and
/// a day); the scheduled event deletes, past it, what nothing names, leaves
/// what a row names to the row, and waits on a reading still pending.
#[test]
fn a_minted_upload_never_sent_is_reclaimed_after_its_deadline_and_a_sent_one_is_not() {
    on_a_small_stack(|| {
        let world = World::new();
        let rows = Rows(&world.db);
        let deadline = NOW + 600 + MINTED_MARGIN_SECS;
        let never = format!("{}/never-sent.beef", sender());
        let sent = format!("{}/sent.beef", sender());
        let pending = format!("{}/pending.beef", sender());
        for key in [&never, &sent, &pending] {
            block_on(RowRefs::mint(&rows, key, deadline)).unwrap();
            world
                .blobs
                .objects
                .borrow_mut()
                .insert(key.clone(), (vec![7; 10], "uploaded".into()));
        }
        // The sent one: a send names it (its own bytes, a valid payment).
        world.blobs.objects.borrow_mut().remove(&sent);
        let chain = chain_atomic_beef(3, 0);
        let sent_key: &'static str = Box::leak(sent.clone().into_boxed_str());
        block_on(send_into(
            &world,
            &chain,
            Some(sent_key),
            true,
            "m-1",
            "unused",
        ));
        // The pending one: a reading saved its place beside it.
        world
            .blobs
            .states
            .borrow_mut()
            .insert(format!("door-state/{pending}"), vec![1]);

        let seams = seams!(world, rows);
        assert_eq!(
            block_on(reclaim_minted(&seams, deadline - 1, 25)).unwrap(),
            Expired::default(),
            "nothing before the deadline"
        );
        assert_eq!(
            block_on(reclaim_minted(&seams, deadline, 25)).unwrap(),
            Expired {
                deleted: 1,
                named: 1,
                put_off: 1
            }
        );
        assert!(!world.has(&never), "the never-sent upload is reclaimed");
        assert!(world.has(&sent), "the sent one is the row's");
        assert!(world.has(&pending), "the pending one waits");
        // The two looked at are forgotten; the pending one comes back in an
        // hour.
        assert_eq!(
            block_on(RowRefs::minted_due(&rows, deadline + 3_599, 25)).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            block_on(RowRefs::minted_due(&rows, deadline + 3_600, 25)).unwrap(),
            vec![pending.clone()]
        );
    });
}

// ---- R403-M1: no in-place copy ----

/// bsv-low #591 R403-M1: through 0.4.3 an upload kept by a send that did not
/// name the relay as its reader was opened whole and written again to the
/// same key, in the request, after the verdict: the etag changed, so a row
/// or a fee naming the old etag named "another upload". Since 0.4.4 the
/// reader is named at mint time (a signed header of the presigned PUT), and
/// an object at rest with no reader has it recorded beside its key in the
/// row. A 135 MB upload is named without a byte read and keeps its etag.
#[test]
fn a_135_mb_object_at_rest_is_named_without_a_byte_read_and_its_etag_never_changes() {
    on_a_small_stack(|| {
        let world = World::new();
        let key = UPLOADED;
        world
            .blobs
            .objects
            .borrow_mut()
            .insert(key.to_string(), (vec![0; 135_000_000], "uploaded".into()));
        let door = Stamp {
            size: 135_000_000,
            etag: "uploaded".into(),
        };
        let payment = json!({
            "beefR2Key": key,
            "outputs": [delivery_output(), recipient_output()],
        });
        let stored_rows = Rows(&world.db);
        let handed = block_on(hand_off(
            &seams!(world, stored_rows),
            &Paid {
                payment: &payment,
                r2_key: Some(key),
                spooled: None,
                spool_key: "unused",
                server_output: Some(&delivery_output()),
                stamp: Some(&door),
                txid: Some(&"ab".repeat(32)),
                rows: true,
                reader: &relay(),
                now: NOW,
            },
        ))
        .expect("handed off");
        assert_eq!(world.blobs.opened.get(), 0, "not a byte read");
        assert_eq!(world.blobs.spools.get(), 0, "nothing written");
        assert_eq!(
            world.blobs.objects.borrow()[key].1,
            "uploaded",
            "the etag holds"
        );
        assert_eq!(handed.payment["beefEtag"], "uploaded");
        assert_eq!(
            handed.payment["beefReader"],
            relay(),
            "the reader beside the key"
        );
        assert_eq!(handed.fee, Fee::Deferred);
        assert_eq!(world.ledger.rows.borrow()[0].etag, "uploaded");
    });
}

// ---- R403-L1: a held fee ends; a transient one has a ceiling ----

fn fee_at(key: &str, etag: &str, args: &str, attempts: u32) -> DeferredFee {
    DeferredFee {
        key: key.to_string(),
        etag: etag.to_string(),
        txid: "aa".into(),
        args: args.to_string(),
        named: false,
        attempts,
        next_at: 0,
    }
}

/// bsv-low #591 R403-L1: through 0.4.3 a fee held for a reason that cannot
/// clear by itself took the transient failure's backoff, daily, without end.
/// Since 0.4.4 each such reason ends the fee at once with its reason on its
/// row and on the health figure, and the drain never takes it up again; a
/// transient refusal keeps the backoff up to `FEE_ATTEMPTS_CEILING`, then
/// ends; a refusal that says wallet-infra cannot read the relay's bucket is
/// recorded as the relay's word, the health figure names it, and no fee is
/// deferred into that wallet-infra while it stands.
#[test]
fn each_held_reason_ends_the_fee_and_the_health_figure_says_so() {
    on_a_small_stack(|| {
        let world = World::new();
        let rows = Rows(&world.db);
        let args = fee_args_text();
        let put = |key: &str, etag: &str| {
            world
                .blobs
                .objects
                .borrow_mut()
                .insert(key.to_string(), (vec![1; 10], etag.to_string()));
        };
        put("02a/other.beef", "now");
        put("02a/bad-args.beef", "e1");
        put("02a/transient.beef", "e1");
        put("02a/last-try.beef", "e1");
        for fee in [
            fee_at("02a/other.beef", "then", &args, 0),
            fee_at("02a/gone.beef", "e1", &args, 0),
            fee_at("02a/bad-args.beef", "e1", "not json", 0),
            fee_at("02a/transient.beef", "e1", &args, 0),
            fee_at("02a/last-try.beef", "e1", &args, FEE_ATTEMPTS_CEILING - 1),
        ] {
            world.ledger.rows.borrow_mut().push(fee);
        }
        world.wallet.down.set(true);
        let seams = seams!(world, rows);
        let drained = block_on(drain_fees(&seams, NOW, 10)).unwrap();
        assert_eq!((drained.settled, drained.put_off, drained.ended), (0, 1, 4));
        let ended: HashMap<String, String> = world.ledger.ended.borrow().iter().cloned().collect();
        assert_eq!(ended["02a/other.beef"], "another upload is at the key");
        assert_eq!(ended["02a/gone.beef"], "the object is not in the store");
        assert_eq!(
            ended["02a/bad-args.beef"],
            "the row's arguments do not parse"
        );
        assert_eq!(
            ended["02a/last-try.beef"],
            format!(
                "not recorded after {} attempts: wallet-infra answered 502",
                FEE_ATTEMPTS_CEILING
            )
        );
        // The transient one is still owed, one attempt on.
        let owed = world.ledger.rows.borrow().clone();
        assert_eq!(owed.len(), 1);
        assert_eq!(
            (owed[0].key.as_str(), owed[0].attempts),
            ("02a/transient.beef", 1)
        );
        // The drain takes up no ended fee again.
        let again = block_on(drain_fees(&seams, NOW + 86_400 * 2, 10)).unwrap();
        assert_eq!(again.ended, 0);

        // No bucket named: ends at once too.
        world.blobs.nameless.set(true);
        world.wallet.down.set(false);
        let nameless = block_on(drain_fees(&seams, NOW + 86_400 * 4, 10)).unwrap();
        assert_eq!(nameless.ended, 1);
        assert_eq!(
            world.ledger.ended.borrow().last().unwrap().1,
            "the deployment names no bucket for the reference"
        );
        world.blobs.nameless.set(false);

        let figure = block_on(health_figure(&world.ledger)).unwrap();
        eprintln!("handoff_at_rest: health {figure}");
        assert_eq!(figure["owed"], 0);
        assert_eq!(figure["ended"], 5);
        assert_eq!(
            figure["lastEnded"],
            "the deployment names no bucket for the reference"
        );
        assert!(figure.get("walletInfra").is_none());
    });
}

#[test]
fn a_wallet_infra_that_cannot_read_the_bucket_is_named_and_no_fee_is_deferred_into_it() {
    on_a_small_stack(|| {
        // A deferred fee meets wallet-infra's own word for a bucket it does
        // not bind (rust-wallet-infra@50a282f src/beef_at_rest.rs:430-434).
        let sent = send_with(chain_atomic_beef(10, 0), Some(UPLOADED), true, true);
        assert_eq!(sent.handed.fee, Fee::Deferred);
        let word = "Internalize failed: beefAtRest: bucket bsv-messagebox-beefs is not bound here (this Worker reads wallet-beefs)";
        struct Refusing(String);
        #[async_trait::async_trait(?Send)]
        impl FeeWallet for Refusing {
            async fn internalize(&self, _args: &Value) -> Result<bool, String> {
                Err(self.0.clone())
            }
        }
        let wallet = Refusing(word.to_string());
        let rows = Rows(&sent.db);
        let seams = Seams {
            blobs: &sent.blobs,
            wallet: &wallet,
            ledger: &sent.ledger,
            rows: &rows,
            announcer: None,
        };
        let drained = block_on(drain_fees(&seams, NOW, 10)).unwrap();
        assert_eq!(drained.ended, 1, "ended at once, not retried");
        let figure = block_on(health_figure(&sent.ledger)).unwrap();
        eprintln!("handoff_at_rest: health {figure}");
        assert_eq!(figure["walletInfra"]["readsTheBucket"], false);
        assert_eq!(
            figure["walletInfra"]["word"],
            format!("wallet-infra cannot read the relay's bucket: {}", word)
        );

        // The next payment too large to record in the request: not deferred
        // into that wallet-infra; it ends with its reason, the message goes.
        let world = World::new();
        *world.ledger.word.borrow_mut() = sent.ledger.word.borrow().clone();
        let chain = chain_atomic_beef(20_000, 0);
        assert!(chain.beef.len() as u64 > 1024 * 1024);
        let spool = format!("{}/5b0c1f6e2d3a4c7b8e9f0a1b2c3d4e5f.beef", sender());
        let (_, handed) = block_on(send_into(&world, &chain, None, true, "m-1", &spool));
        assert_eq!(handed.fee, Fee::Ended);
        assert!(
            world.ledger.rows.borrow().is_empty(),
            "nothing owed into it"
        );
        assert!(world.ledger.ended.borrow()[0]
            .1
            .starts_with("not deferred: wallet-infra cannot read the relay's bucket"));
        assert_eq!(world.listed().len(), 1, "the message is delivered");
        // A day on, a fee is deferred into it again, to be tried once more.
        let later = World::new();
        *later.ledger.word.borrow_mut() = Some(("w".into(), NOW - 86_400));
        let (_, handed) = block_on(send_into(&later, &chain, None, true, "m-1", &spool));
        assert_eq!(handed.fee, Fee::Deferred);
    });
}

fn fee_args_text() -> String {
    rust_message_box::handoff::fee_args(&delivery_output(), &json!({})).to_string()
}
