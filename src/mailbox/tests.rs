//! The mailbox's machine on a real SQLite (rusqlite, dev-only) over the same
//! statements the Durable Object runs, as R1 tested the consumer: the insert,
//! the bound at 10,000 rows and at 1 GiB, the counters across a send and an
//! acknowledgment, the listing's order and cut, the legacy merge by id
//! against D1's own statements, the archive's round trip and the replay.

use super::*;
use crate::archive::{archive_held_sql, held_map, parse, plan, statements, HeldRow, Verdict};
use crate::d1::QVal;
use crate::storage::{INSERT_MESSAGE_SQL, LIST_MESSAGES_SQL};
use rusqlite::types::Value as Sql;

/// rusqlite as the machine's store.
struct Lite(rusqlite::Connection);

impl MailboxSql for Lite {
    fn run(&self, sql: &str, params: &[Val]) -> Result<Vec<Vec<Val>>, String> {
        let mut stmt = self.0.prepare(sql).map_err(|e| e.to_string())?;
        let n = stmt.column_count();
        let ps: Vec<Sql> = params
            .iter()
            .map(|v| match v {
                Val::Null => Sql::Null,
                Val::Int(i) => Sql::Integer(*i),
                Val::Text(s) => Sql::Text(s.clone()),
            })
            .collect();
        let mut rows = stmt
            .query(rusqlite::params_from_iter(ps))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let mut row = Vec::with_capacity(n);
            for i in 0..n {
                row.push(match r.get::<_, Sql>(i).map_err(|e| e.to_string())? {
                    Sql::Null => Val::Null,
                    Sql::Integer(i) => Val::Int(i),
                    Sql::Real(f) => Val::Int(f as i64),
                    Sql::Text(s) => Val::Text(s),
                    Sql::Blob(b) => Val::Text(String::from_utf8_lossy(&b).into_owned()),
                });
            }
            out.push(row);
        }
        Ok(out)
    }
}

const ME: &str = "02aa";
const T0: u64 = 1_792_000_000_000;

fn hub() -> Lite {
    let db = Lite(rusqlite::Connection::open_in_memory().unwrap());
    ensure_schema(&db).unwrap();
    bind_identity(&db, ME).unwrap();
    db
}

fn row(id: &str, message_box: &str, body: &str) -> NewRow {
    NewRow {
        message_id: id.into(),
        message_box: message_box.into(),
        sender: "03bb".into(),
        body: body.into(),
    }
}

fn put(db: &Lite, id: &str, body: &str) -> Inserted {
    insert(db, &row(id, "inbox", body), false, T0, Bounds::RULED).unwrap()
}

fn state_of(db: &Lite, id: &str) -> Option<(String, i64, i64, i64, Option<String>)> {
    db.0.query_row(
        "SELECT state, version, owed, archived_version, body FROM mailbox_rows WHERE message_id = ?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .ok()
}

fn ids(rows: &[MessageDbRow]) -> Vec<&str> {
    rows.iter()
        .filter_map(|r| r.message_id.as_deref())
        .collect()
}

#[test]
fn the_layout_is_idempotent_and_every_table_carries_its_doc() {
    let db = hub();
    ensure_schema(&db).unwrap();
    ensure_schema(&db).unwrap();
    assert_eq!(counters(&db).unwrap(), (0, 0));
    let src = include_str!("schema.rs");
    for table in [
        "mailbox_rows",
        "mailbox_counters",
        "mailbox_meta",
        "permissions_copy",
    ] {
        assert!(
            src.contains(&format!("/// `{table}`:")),
            "{table} has its doc comment"
        );
    }
}

#[test]
fn the_listing_and_the_replay_read_by_their_indexes() {
    let db = hub();
    let plan_of = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> String {
        let mut stmt = db.0.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt
            .query_map(params, |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        rows.join(" | ")
    };
    let p = plan_of(MAILBOX_LIST_SQL, &[&"inbox", &100i64, &1000i64]);
    assert!(p.contains("USING INDEX mailbox_rows_listing"), "{p}");
    assert!(!p.contains("SCAN mailbox_rows"), "{p}");
    let p = plan_of(
        "SELECT message_id FROM mailbox_rows INDEXED BY mailbox_rows_owed \
         WHERE owed = 1 AND (enqueued_at IS NULL OR enqueued_at <= ?) ORDER BY enqueued_at LIMIT 16",
        &[&0i64],
    );
    assert!(p.contains("mailbox_rows_owed"), "{p}");
}

#[test]
fn a_hub_serves_one_identity() {
    let db = hub();
    assert!(bind_identity(&db, ME).is_ok());
    assert!(bind_identity(&db, "02cc").is_err());
    assert!(bind_identity(&db, "").is_err());
    assert_eq!(identity_of(&db).unwrap().as_deref(), Some(ME));
}

#[test]
fn e1_an_insert_holds_the_row_live_at_version_one_and_moves_the_counters() {
    let db = hub();
    assert_eq!(put(&db, "m1", "hello"), Inserted::Stored);
    assert_eq!(put(&db, "m2", "héllo"), Inserted::Stored);
    // Bytes are the stored text's UTF-8 length, D1's length(CAST(body AS BLOB)).
    assert_eq!(counters(&db).unwrap(), (2, 5 + 6));
    assert_eq!(
        state_of(&db, "m1"),
        Some(("live".into(), 1, 1, 0, Some("hello".into())))
    );
    let blob_len: i64 =
        db.0.query_row(
            "SELECT length(CAST(body AS BLOB)) FROM mailbox_rows WHERE message_id = 'm2'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(blob_len, 6);
    let at: String =
        db.0.query_row(
            "SELECT created_at FROM mailbox_rows WHERE message_id = 'm1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(at, sqlite_time(T0));
    assert_eq!(
        crate::storage::to_iso8601(Some(&at)),
        "2026-10-14T17:46:40.000Z"
    );
}

#[test]
fn e2_e3_a_retried_hop_finds_its_own_row_and_a_clean_one_is_a_duplicate() {
    let db = hub();
    assert_eq!(put(&db, "m1", "hello"), Inserted::Stored);
    // A clean insert under a held id: the duplicate, whatever the body.
    assert_eq!(put(&db, "m1", "hello"), Inserted::Duplicate);
    // A retried hop whose earlier attempt landed: stored, nothing written.
    let r = insert(&db, &row("m1", "inbox", "hello"), true, T0, Bounds::RULED).unwrap();
    assert_eq!(r, Inserted::Retried);
    // A retried hop with another body, box or sender is not this send's row.
    for other in [
        row("m1", "inbox", "other"),
        row("m1", "outbox", "hello"),
        NewRow {
            sender: "03cc".into(),
            ..row("m1", "inbox", "hello")
        },
    ] {
        assert_eq!(
            insert(&db, &other, true, T0, Bounds::RULED).unwrap(),
            Inserted::Duplicate
        );
    }
    assert_eq!(counters(&db).unwrap(), (1, 5));
}

#[test]
fn e4_the_ruled_bound_refuses_the_10001st_row_and_holds_the_10000th() {
    let db = hub();
    db.0.execute_batch("BEGIN").unwrap();
    for i in 0..9_999 {
        assert_eq!(put(&db, &format!("m{i}"), "x"), Inserted::Stored);
    }
    db.0.execute_batch("COMMIT").unwrap();
    assert_eq!(counters(&db).unwrap(), (9_999, 9_999));
    // One below the bound: held.
    assert_eq!(put(&db, "m9999", "x"), Inserted::Stored);
    assert_eq!(counters(&db).unwrap(), (10_000, 10_000));
    // At the bound: refused, nothing written.
    assert_eq!(
        put(&db, "m10000", "x"),
        Inserted::Full(Full {
            resource: "messages".into(),
            limit: 10_000,
            held: 10_000,
        })
    );
    assert_eq!(counters(&db).unwrap(), (10_000, 10_000));
    assert!(state_of(&db, "m10000").is_none());
    // An acknowledgment frees the slot.
    let a = acknowledge(&db, &["m0".into()], false, T0).unwrap();
    assert_eq!(a.acknowledged, vec!["m0".to_string()]);
    assert_eq!(put(&db, "m10000", "x"), Inserted::Stored);
}

#[test]
fn e4_the_bytes_bound_is_1_gib_of_stored_text() {
    let db = hub();
    let b = MAILBOX_BYTES_LIMIT as i64;
    db.0.execute(
        "UPDATE mailbox_counters SET bytes_held = ? WHERE id = 1",
        [b - 10],
    )
    .unwrap();
    // Up to the bound exactly: held.
    assert_eq!(put(&db, "m1", "0123456789"), Inserted::Stored);
    assert_eq!(counters(&db).unwrap(), (1, MAILBOX_BYTES_LIMIT));
    // One byte past it: refused, nothing written.
    assert_eq!(
        put(&db, "m2", "x"),
        Inserted::Full(Full {
            resource: "bytes".into(),
            limit: 1_073_741_824,
            held: 1_073_741_824,
        })
    );
    assert!(state_of(&db, "m2").is_none());
    assert_eq!(counters(&db).unwrap(), (1, MAILBOX_BYTES_LIMIT));
}

#[test]
fn the_full_mailbox_answers_the_references_429_and_the_three_added_fields() {
    let full = Full {
        resource: "messages".into(),
        limit: 10_000,
        held: 10_000,
    };
    let (body, status) = full_answer(&full, ME);
    assert_eq!(status, 429);
    assert_eq!(
        body,
        json!({
            "status": "error",
            "code": "ERR_INBOX_QUOTA_EXCEEDED",
            "description": "The recipient inbox storage quota has been reached. Retry after messages are acknowledged or expire.",
            "resource": "messages",
            "limit": 10000,
            "held": 10000,
            "recipient": ME,
            "freedBy": "acknowledgeMessage",
        })
    );
}

#[test]
fn e9_the_counters_follow_a_send_and_an_acknowledgment() {
    let db = hub();
    put(&db, "m1", "aaaa");
    put(&db, "m2", "bb");
    put(&db, "m3", "c");
    assert_eq!(counters(&db).unwrap(), (3, 7));
    let a = acknowledge(&db, &["m2".into(), "m2".into(), "zz".into()], false, T0 + 5).unwrap();
    assert_eq!(a.acknowledged, vec!["m2".to_string()]);
    assert_eq!(a.missing, vec!["zz".to_string()]);
    assert_eq!(counters(&db).unwrap(), (2, 5));
    // Never archived: the body is kept for the acknowledgment's archive write.
    assert_eq!(
        state_of(&db, "m2"),
        Some(("acknowledged".into(), 2, 1, 0, Some("bb".into())))
    );
    // A clean second acknowledgment of it is missing; a retried hop's counts.
    let a = acknowledge(&db, &["m2".into()], false, T0).unwrap();
    assert_eq!(a.missing, vec!["m2".to_string()]);
    let a = acknowledge(&db, &["m2".into()], true, T0).unwrap();
    assert_eq!(a.acknowledged, vec!["m2".to_string()]);
    assert_eq!(counters(&db).unwrap(), (2, 5), "the counters move once");
    // An archived row drops its body at the acknowledgment.
    archive_done(
        &db,
        &[Done {
            message_id: "m1".into(),
            version: 1,
            collision: false,
        }],
    )
    .unwrap();
    acknowledge(&db, &["m1".into()], false, T0).unwrap();
    assert_eq!(
        state_of(&db, "m1"),
        Some(("acknowledged".into(), 2, 1, 1, None))
    );
    assert_eq!(counters(&db).unwrap(), (1, 1));
}

#[test]
fn e8_a_listing_is_the_boxs_live_rows_in_insertion_order_cut_at_100_and_the_budget() {
    let db = hub();
    for i in 0..105 {
        let b = if i % 2 == 0 { "inbox" } else { "other" };
        insert(
            &db,
            &row(&format!("m{i:03}"), b, "0123456789"),
            false,
            T0 + i,
            Bounds::RULED,
        )
        .unwrap();
    }
    for i in 105..160 {
        put(&db, &format!("m{i:03}"), "0123456789");
    }
    acknowledge(&db, &["m002".into()], false, T0).unwrap();
    let all = list(&db, "inbox", LIST_LIMIT, crate::handoff::LIST_INLINE_BYTES).unwrap();
    assert_eq!(all.len(), 100);
    assert_eq!(ids(&all)[..3], ["m000", "m004", "m006"]);
    assert!(
        !ids(&all).contains(&"m002"),
        "an acknowledged row is never listed"
    );
    assert!(ids(&all).windows(2).all(|w| w[0] < w[1]), "insertion order");
    // The budget: the leading rows whose bodies add up to at most 35 bytes.
    let cut = list(&db, "inbox", LIST_LIMIT, 35).unwrap();
    assert_eq!(ids(&cut), ["m000", "m004", "m006"]);
    assert_eq!(cut[0].body.as_deref(), Some("0123456789"));
    assert_eq!(cut[0].sender.as_deref(), Some("03bb"));
    assert!(list(&db, "nobox", 100, 100).unwrap().is_empty());
}

#[test]
fn e13_a_cold_hub_lists_what_it_listed_before() {
    let path = std::env::temp_dir().join(format!("mbx-cold-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let before = {
        let db = Lite(rusqlite::Connection::open(&path).unwrap());
        ensure_schema(&db).unwrap();
        bind_identity(&db, ME).unwrap();
        put(&db, "m1", "one");
        put(&db, "m2", "two");
        acknowledge(&db, &["m1".into()], false, T0).unwrap();
        list(&db, "inbox", 100, 1 << 20).unwrap()
    };
    let db = Lite(rusqlite::Connection::open(&path).unwrap());
    ensure_schema(&db).unwrap();
    assert_eq!(list(&db, "inbox", 100, 1 << 20).unwrap(), before);
    assert_eq!(counters(&db).unwrap(), (1, 3));
    let _ = std::fs::remove_file(&path);
}

// -- The legacy merge, against D1's own schema and listing statement --

const D1_MIGRATIONS: [&str; 11] = [
    include_str!("../../migrations/0001_initial.sql"),
    include_str!("../../migrations/0002_transcript_retention.sql"),
    include_str!("../../migrations/0003_fee_internalize.sql"),
    include_str!("../../migrations/0004_beef_key.sql"),
    include_str!("../../migrations/0005_announce_owed.sql"),
    include_str!("../../migrations/0006_send_budget.sql"),
    include_str!("../../migrations/0007_beef_reclaiming.sql"),
    include_str!("../../migrations/0008_beef_minted.sql"),
    include_str!("../../migrations/0009_fee_terminal.sql"),
    include_str!("../../migrations/0010_turn_credentials.sql"),
    include_str!("../../migrations/0011_archive_version.sql"),
];

fn d1() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    for m in D1_MIGRATIONS {
        db.execute_batch(m).unwrap();
    }
    db.execute(
        "INSERT INTO message_boxes (identity_key, type) VALUES (?, 'inbox')",
        [ME],
    )
    .unwrap();
    db
}

fn d1_box(db: &rusqlite::Connection) -> i64 {
    db.query_row(
        "SELECT message_box_id FROM message_boxes WHERE identity_key = ? AND type = 'inbox'",
        [ME],
        |r| r.get(0),
    )
    .unwrap()
}

/// The old path's insert (`storage::INSERT_MESSAGE_SQL`).
fn d1_put(db: &rusqlite::Connection, id: &str, body: &str) {
    let b = d1_box(db);
    db.execute(
        INSERT_MESSAGE_SQL,
        rusqlite::params![id, b, "03bb", ME, body, Option::<String>::None],
    )
    .unwrap();
}

/// The old path's listing (`storage::LIST_MESSAGES_SQL`), as `list_messages`.
fn d1_list(db: &rusqlite::Connection) -> Vec<MessageDbRow> {
    let b = d1_box(db);
    let mut stmt = db.prepare(LIST_MESSAGES_SQL).unwrap();
    stmt.query_map(
        rusqlite::params![ME, b, 100, crate::handoff::LIST_INLINE_BYTES as i64],
        |r| {
            Ok(MessageDbRow {
                message_id: r.get(0)?,
                body: r.get(1)?,
                sender: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        },
    )
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[test]
fn the_legacy_merge_leads_with_the_old_paths_rows_and_the_mailbox_wins_by_id() {
    let hub = hub();
    let old = d1();
    d1_put(&old, "old1", "legacy one");
    d1_put(&old, "old2", "legacy two");
    // An id both hold (an archived copy of a mailbox row): the mailbox's wins.
    d1_put(&old, "both", "the archive's copy");
    put(&hub, "both", "the mailbox's row");
    put(&hub, "new1", "fresh");
    // An id the mailbox holds acknowledged: D1's live copy never comes back.
    d1_put(&old, "acked", "stale live copy");
    put(&hub, "acked", "x");
    acknowledge(&hub, &["acked".into()], false, T0).unwrap();

    let legacy = d1_list(&old);
    let held = held_ids(
        &hub,
        &legacy
            .iter()
            .filter_map(|r| r.message_id.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mine = list(&hub, "inbox", 100, 1 << 20).unwrap();
    let merged = merge(
        legacy,
        mine,
        &held,
        MergeOrder::D1First,
        100,
        crate::handoff::LIST_INLINE_BYTES,
    );
    assert_eq!(ids(&merged), ["old1", "old2", "both", "new1"]);
    assert_eq!(merged[2].body.as_deref(), Some("the mailbox's row"));
    // Each listed row carries the wire's fields; the times read as ISO 8601.
    for r in &merged {
        assert!(crate::storage::to_iso8601(r.created_at.as_deref()).ends_with(".000Z"));
    }
}

#[test]
fn the_drain_merge_leads_with_the_mailbox_and_both_cuts_hold_across_the_sides() {
    let held: HashSet<String> = ["b".to_string()].into();
    let r = |id: &str, body: &str| MessageDbRow {
        message_id: Some(id.into()),
        body: Some(body.into()),
        ..Default::default()
    };
    let d1 = vec![r("b", "d1-b"), r("c", "cc"), r("d", "dd")];
    let mailbox = vec![r("a", "aa"), r("b", "hub-b")];
    let m = merge(
        d1.clone(),
        mailbox.clone(),
        &held,
        MergeOrder::MailboxFirst,
        100,
        1 << 20,
    );
    assert_eq!(ids(&m), ["a", "b", "c", "d"]);
    assert_eq!(m[1].body.as_deref(), Some("hub-b"));
    let m = merge(
        d1.clone(),
        mailbox.clone(),
        &held,
        MergeOrder::MailboxFirst,
        3,
        1 << 20,
    );
    assert_eq!(ids(&m), ["a", "b", "c"]);
    // 2 + 5 + 2 = 9 bytes fit; the fourth row would pass 10.
    let m = merge(d1, mailbox, &held, MergeOrder::MailboxFirst, 100, 10);
    assert_eq!(ids(&m), ["a", "b", "c"]);
}

#[test]
fn the_legacy_acknowledgment_takes_only_the_rows_d1_holds_live() {
    let hub = hub();
    let mut old = d1();
    d1_put(&old, "legacy", "an old path row");
    // A mailbox row archived, acknowledged, archived again and gone from the
    // hub: D1 keeps an acknowledged mark, which is not a row to acknowledge.
    put(&hub, "gone", "x");
    let ins = archive_message(&archive_rows(&hub, &["gone".into()]).unwrap()[0], ME);
    acknowledge(&hub, &["gone".into()], false, T0).unwrap();
    let ack = archive_message(&archive_rows(&hub, &["gone".into()]).unwrap()[0], ME);
    archive_apply(&mut old, &[ins, ack]);
    let ids = [
        "legacy".to_string(),
        "gone".to_string(),
        "never".to_string(),
    ];
    let sql = crate::storage::live_message_ids_sql(ids.len());
    let mut stmt = old.prepare(&sql).unwrap();
    let mut params: Vec<String> = vec![ME.into()];
    params.extend(ids.iter().cloned());
    let live: Vec<String> = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(live, ["legacy"]);
    // Another recipient's live row under an id is not the caller's.
    let mut stmt = old
        .prepare(&crate::storage::live_message_ids_sql(1))
        .unwrap();
    let n = stmt
        .query_map(rusqlite::params!["02cc", "legacy"], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .count();
    assert_eq!(n, 0);
}

// -- The archive's round trip: the hub's message, R1's consumer, the done --

/// R1's consumer on rusqlite: the held read, the plan, the statements.
fn archive_apply(
    db: &mut rusqlite::Connection,
    batch: &[crate::archive::ArchiveMessage],
) -> Vec<Verdict> {
    let mut ids: Vec<&str> = batch.iter().map(|m| m.message_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let rows: Vec<HeldRow> = {
        let mut stmt = db.prepare(&archive_held_sql(ids.len())).unwrap();
        stmt.query_map(rusqlite::params_from_iter(ids.iter()), |r| {
            Ok(HeldRow {
                message_id: r.get(0)?,
                recipient: r.get(1)?,
                archive_version: Some(r.get::<_, i64>(2)? as f64),
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    };
    let verdicts = plan(batch, &held_map(rows));
    let tx = db.transaction().unwrap();
    for (m, v) in batch.iter().zip(&verdicts) {
        if *v != Verdict::Apply {
            continue;
        }
        for (sql, params) in statements(m) {
            let ps: Vec<Sql> = params
                .iter()
                .map(|p| match p {
                    QVal::Int(i) => Sql::Integer(*i),
                    QVal::Text(s) => Sql::Text(s.clone()),
                    QVal::Bool(b) => Sql::Integer(i64::from(*b)),
                    QVal::Float(f) => Sql::Real(*f),
                    QVal::Null => Sql::Null,
                })
                .collect();
            tx.execute(sql, rusqlite::params_from_iter(ps)).unwrap();
        }
    }
    tx.commit().unwrap();
    verdicts
}

/// Round-trip one message through the queue's JSON, as the consumer reads it.
fn through_queue(m: &crate::archive::ArchiveMessage) -> crate::archive::ArchiveMessage {
    parse(serde_json::from_str(&serde_json::to_string(m).unwrap()).unwrap()).unwrap()
}

fn d1_row(db: &rusqlite::Connection, id: &str) -> Option<(String, i64, bool)> {
    db.query_row(
        "SELECT body, archive_version, acknowledged_at IS NOT NULL FROM messages WHERE message_id = ?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

#[test]
fn a_mailbox_row_is_archived_then_acknowledged_then_gone_from_the_hub() {
    let hub = hub();
    let mut old = d1();
    put(&hub, "m1", "hello");

    // E7: the insert's message, R1's shape.
    let rows = archive_rows(&hub, &["m1".into()]).unwrap();
    let m = through_queue(&archive_message(&rows[0], ME));
    assert_eq!(
        (m.change, m.version, m.body.as_deref(), m.body_in_hub),
        (Change::Insert, 1, Some("hello"), false)
    );
    let v = archive_apply(&mut old, std::slice::from_ref(&m));
    assert_eq!(v, [Verdict::Apply]);
    assert_eq!(d1_row(&old, "m1"), Some(("hello".into(), 1, false)));
    // E11 at version 1: archived, no longer owed, still listed from the hub.
    let told = crate::archive::done_by_recipient(std::slice::from_ref(&m), &v);
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].0, ME);
    archive_done(&hub, &told[0].1).unwrap();
    assert_eq!(
        state_of(&hub, "m1"),
        Some(("live".into(), 1, 0, 1, Some("hello".into())))
    );
    assert_eq!(ids(&list(&hub, "inbox", 100, 1 << 20).unwrap()), ["m1"]);

    // E9 then the acknowledgment's message (no body: the archive holds it).
    acknowledge(&hub, &["m1".into()], false, T0).unwrap();
    let rows = archive_rows(&hub, &["m1".into()]).unwrap();
    let a = through_queue(&archive_message(&rows[0], ME));
    assert_eq!(
        (a.change, a.version, a.body.as_deref()),
        (Change::Acknowledge, 2, None)
    );
    // A repeated insert message after it changes nothing.
    let v = archive_apply(&mut old, &[a.clone(), m.clone()]);
    assert_eq!(v, [Verdict::Apply, Verdict::Superseded]);
    assert_eq!(d1_row(&old, "m1"), Some(("hello".into(), 2, true)));
    // The D1 listing does not return it, and the hub deletes it at version 2.
    assert!(d1_list(&old).is_empty());
    let told = crate::archive::done_by_recipient(&[a, m], &v);
    archive_done(&hub, &told[0].1).unwrap();
    assert!(state_of(&hub, "m1").is_none());
}

#[test]
fn an_acknowledgment_before_any_archive_carries_the_body_and_the_insert_after_it_changes_nothing() {
    let hub = hub();
    let mut old = d1();
    put(&hub, "m1", "hello");
    let ins = archive_message(&archive_rows(&hub, &["m1".into()]).unwrap()[0], ME);
    acknowledge(&hub, &["m1".into()], false, T0).unwrap();
    let ack = archive_message(&archive_rows(&hub, &["m1".into()]).unwrap()[0], ME);
    assert_eq!(ack.body.as_deref(), Some("hello"));
    assert_eq!(
        archive_apply(&mut old, std::slice::from_ref(&ack)),
        [Verdict::Apply]
    );
    assert_eq!(
        archive_apply(&mut old, std::slice::from_ref(&ins)),
        [Verdict::Repeat]
    );
    assert_eq!(d1_row(&old, "m1"), Some(("hello".into(), 2, true)));
    // The insert's done (version 1) leaves the acknowledged row; version 2 deletes it.
    archive_done(
        &hub,
        &crate::archive::done_by_recipient(&[ins], &[Verdict::Repeat])[0].1,
    )
    .unwrap();
    assert_eq!(
        state_of(&hub, "m1"),
        Some(("acknowledged".into(), 2, 1, 1, None))
    );
    archive_done(
        &hub,
        &crate::archive::done_by_recipient(&[ack], &[Verdict::Apply])[0].1,
    )
    .unwrap();
    assert!(state_of(&hub, "m1").is_none());
}

#[test]
fn a_body_too_long_for_the_queue_stays_in_the_hub_and_is_read_back() {
    let hub = hub();
    let mut old = d1();
    let long = "y".repeat(ARCHIVE_INLINE_MAX + 1);
    put(&hub, "big", &long);
    let rows = archive_rows(&hub, &["big".into()]).unwrap();
    let m = archive_message(&rows[0], ME);
    assert!(m.body_in_hub && m.body.is_none());
    let json = serde_json::to_string(&m).unwrap();
    assert!(
        json.len() < 128 * 1000,
        "{} bytes fit a queue message",
        json.len()
    );
    let mut m = through_queue(&m);
    assert_eq!(
        crate::archive::bodies_in_hub(std::slice::from_ref(&m)),
        vec![(ME.to_string(), vec![0])]
    );
    // The consumer's read of /internal/archive-read.
    let read = archive_rows(&hub, &["big".into()]).unwrap();
    m.body = crate::archive::body_from_hub(&m, &read);
    assert_eq!(m.body.as_deref().map(str::len), Some(long.len()));
    assert_eq!(archive_apply(&mut old, &[m]), [Verdict::Apply]);
    assert_eq!(d1_row(&old, "big").unwrap().0.len(), long.len());
    // A short body rides inline and sets no flag on the wire.
    put(&hub, "small", "s");
    let s = archive_message(&archive_rows(&hub, &["small".into()]).unwrap()[0], ME);
    assert!(!serde_json::to_string(&s).unwrap().contains("bodyInHub"));
    // A message whose hub no longer holds a body has nothing to write.
    assert_eq!(crate::archive::body_from_hub(&s, &[]), None);
}

#[test]
fn a_collision_is_kept_and_served_never_owed_and_an_acknowledged_one_goes() {
    let hub = hub();
    put(&hub, "c1", "mine");
    put(&hub, "c2", "mine too");
    acknowledge(&hub, &["c2".into()], false, T0).unwrap();
    let done = |id: &str, v| Done {
        message_id: id.into(),
        version: v,
        collision: true,
    };
    assert_eq!(
        archive_done(&hub, &[done("c1", 1), done("c2", 2)]).unwrap(),
        2
    );
    let (state, _, owed, _, _) = state_of(&hub, "c1").unwrap();
    assert_eq!((state.as_str(), owed), ("live", 0));
    assert!(state_of(&hub, "c2").is_none());
    assert_eq!(ids(&list(&hub, "inbox", 100, 1 << 20).unwrap()), ["c1"]);
    assert!(take_owed_due(&hub, T0 + 10 * REPLAY_AFTER_MS)
        .unwrap()
        .is_empty());
    // A done for an id the hub never held changes nothing.
    assert_eq!(archive_done(&hub, &[done("zz", 1)]).unwrap(), 0);
}

#[test]
fn e12_the_replay_hands_back_at_most_16_owed_rows_past_120_s_and_renews_them() {
    let hub = hub();
    for i in 0..20 {
        put(&hub, &format!("m{i:02}"), "x");
    }
    // Every insert set enqueued_at = T0 (handed to the queue after its answer).
    assert!(take_owed_due(&hub, T0 + REPLAY_AFTER_MS - 1)
        .unwrap()
        .is_empty());
    let batch = take_owed_due(&hub, T0 + REPLAY_AFTER_MS).unwrap();
    assert_eq!(batch.len(), REPLAY_PER_REQUEST);
    let second = take_owed_due(&hub, T0 + REPLAY_AFTER_MS).unwrap();
    assert_eq!(second.len(), 4, "the rest, not the renewed ones");
    assert!(take_owed_due(&hub, T0 + REPLAY_AFTER_MS)
        .unwrap()
        .is_empty());
    // An archived row is never owed again.
    archive_done(
        &hub,
        &[Done {
            message_id: "m00".into(),
            version: 1,
            collision: false,
        }],
    )
    .unwrap();
    let later = take_owed_due(&hub, T0 + 3 * REPLAY_AFTER_MS).unwrap();
    assert_eq!(later.len(), 16);
    assert!(later.iter().all(|r| r.message_id != "m00"));
}

#[test]
fn the_permissions_copy_lives_ten_minutes_and_a_change_clears_it() {
    let hub = hub();
    assert_eq!(permissions_copy(&hub, "03bb", "inbox", T0).unwrap(), None);
    keep_permissions(&hub, "03bb", "inbox", -1, 5, T0).unwrap();
    assert_eq!(
        permissions_copy(&hub, "03bb", "inbox", T0 + PERMISSIONS_COPY_TTL_MS - 1).unwrap(),
        Some((-1, 5))
    );
    assert_eq!(
        permissions_copy(&hub, "03bb", "inbox", T0 + PERMISSIONS_COPY_TTL_MS).unwrap(),
        None
    );
    assert_eq!(permissions_copy(&hub, "03cc", "inbox", T0).unwrap(), None);
    forget_permissions(&hub).unwrap();
    assert_eq!(permissions_copy(&hub, "03bb", "inbox", T0).unwrap(), None);
}
