//! The archive's statements on a real SQLite with the real migrations
//! (rusqlite, dev-only), as the acknowledge statements are in `retention.rs`;
//! the plan and the parse as pure functions.

use super::*;
use crate::storage::{INSERT_MESSAGE_SQL, LIST_MESSAGES_SQL};
use rusqlite::types::Value as Sql;

const MIGRATIONS_0_7_1: [&str; 10] = [
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
];
const MIGRATION_0011: &str = include_str!("../../migrations/0011_archive_version.sql");

fn db_at_0_7_1() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    for m in MIGRATIONS_0_7_1 {
        db.execute_batch(m).unwrap();
    }
    db
}

fn migrated_db() -> rusqlite::Connection {
    let db = db_at_0_7_1();
    db.execute_batch(MIGRATION_0011).unwrap();
    db
}

fn to_sql(v: &QVal) -> Sql {
    match v {
        QVal::Int(i) => Sql::Integer(*i),
        QVal::Text(s) => Sql::Text(s.clone()),
        QVal::Bool(b) => Sql::Integer(i64::from(*b)),
        QVal::Float(f) => Sql::Real(*f),
        QVal::Null => Sql::Null,
    }
}

/// `archive_batch` on rusqlite: the same held read, plan and statements, the
/// writes in one transaction as D1's `batch()`.
fn apply(db: &mut rusqlite::Connection, batch: &[ArchiveMessage]) -> Vec<Verdict> {
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
        .map(|r| r.unwrap())
        .collect()
    };
    let verdicts = plan(batch, &held_map(rows));
    let tx = db.transaction().unwrap();
    for (m, v) in batch.iter().zip(&verdicts) {
        if *v == Verdict::Apply {
            for (sql, params) in statements(m) {
                let params: Vec<Sql> = params.iter().map(to_sql).collect();
                tx.execute(sql, rusqlite::params_from_iter(params)).unwrap();
            }
        }
    }
    tx.commit().unwrap();
    verdicts
}

fn insert(id: &str, version: u64, body: &str) -> ArchiveMessage {
    ArchiveMessage {
        recipient: "rcpt".into(),
        message_id: id.into(),
        version,
        change: Change::Insert,
        message_box: "inbox".into(),
        sender: "sndr".into(),
        body: Some(body.into()),
        created_at: Some("2026-10-23 15:00:00".into()),
        body_in_hub: false,
    }
}

fn ack(id: &str, version: u64, body: Option<&str>) -> ArchiveMessage {
    ArchiveMessage {
        change: Change::Acknowledge,
        body: body.map(Into::into),
        ..insert(id, version, "")
    }
}

/// `(body, archive_version, acknowledged)` of the row under `id`.
fn row(db: &rusqlite::Connection, id: &str) -> Option<(String, i64, bool)> {
    db.query_row(
        "SELECT body, archive_version, acknowledged_at IS NOT NULL FROM messages WHERE message_id = ?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

/// The ids 0.7.1's listing (`LIST_MESSAGES_SQL`) returns for `rcpt`'s inbox.
fn listed(db: &rusqlite::Connection) -> Vec<String> {
    let Ok(box_id) = db.query_row(
        "SELECT message_box_id FROM message_boxes WHERE identity_key = 'rcpt' AND type = 'inbox'",
        [],
        |r| r.get::<_, i64>(0),
    ) else {
        return Vec::new();
    };
    let mut stmt = db.prepare(LIST_MESSAGES_SQL).unwrap();
    stmt.query_map(
        rusqlite::params![
            "rcpt",
            box_id,
            100,
            crate::handoff::LIST_INLINE_BYTES as i64
        ],
        |r| r.get::<_, String>(0),
    )
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

fn plan_of(db: &rusqlite::Connection, sql: &str, n_binds: usize) -> String {
    let mut stmt = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let binds = vec![Sql::Text("x".into()); n_binds];
    stmt.query_map(rusqlite::params_from_iter(binds), |r| r.get::<_, String>(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- the migration

#[test]
fn migration_0011_applies_and_adds_the_column_and_the_index() {
    let db = migrated_db();
    let (default, notnull): (String, bool) = db
        .query_row(
            "SELECT dflt_value, \"notnull\" FROM pragma_table_info('messages') WHERE name = 'archive_version'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((default.as_str(), notnull), ("0", true));
    let cols: Vec<String> = db
        .prepare("SELECT name FROM pragma_index_info('idx_messages_archive')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(cols, ["message_id", "archive_version", "recipient"]);
}

#[test]
fn a_row_stored_before_0011_reads_version_0() {
    let db = db_at_0_7_1();
    db.execute(
        "INSERT INTO message_boxes (identity_key, type) VALUES ('rcpt', 'inbox')",
        [],
    )
    .unwrap();
    db.execute(
        INSERT_MESSAGE_SQL,
        rusqlite::params!["old", 1, "sndr", "rcpt", "b", None::<String>],
    )
    .unwrap();
    db.execute_batch(MIGRATION_0011).unwrap();
    assert_eq!(row(&db, "old"), Some(("b".into(), 0, false)));
}

/// 0.7.1's statements on the migrated schema: they run, they answer as on
/// 0.7.1's, and their plans are 0.7.1's (the new index moves none of them).
#[test]
fn the_0_7_1_statements_run_and_plan_alike_on_the_migrated_schema() {
    let ack_update = crate::retention::ack_update_sql(1, 1);
    let ack_delete = crate::retention::ack_delete_sql(1, 0);
    let ack_delete_retained = crate::retention::ack_delete_sql(1, 1);
    let statements: [(&str, usize); 6] = [
        (LIST_MESSAGES_SQL, 4),
        (ack_update.as_str(), 3),
        (ack_delete.as_str(), 2),
        (ack_delete_retained.as_str(), 3),
        (
            "SELECT sender, recipient, body FROM messages WHERE message_id = ?",
            1,
        ),
        (
            "SELECT body FROM messages WHERE message_id = ? AND recipient = ?",
            2,
        ),
    ];
    let (old, new) = (db_at_0_7_1(), migrated_db());
    for (sql, n) in statements {
        assert_eq!(plan_of(&old, sql, n), plan_of(&new, sql, n), "{sql}");
    }

    // The 0.7.1 cycle on the migrated schema: insert, list, acknowledge.
    let db = new;
    db.execute(
        "INSERT INTO message_boxes (identity_key, type) VALUES ('rcpt', 'inbox')",
        [],
    )
    .unwrap();
    for id in ["a", "b"] {
        assert_eq!(
            db.execute(
                INSERT_MESSAGE_SQL,
                rusqlite::params![id, 1, "sndr", "rcpt", "body", None::<String>],
            )
            .unwrap(),
            1
        );
    }
    assert_eq!(listed(&db), ["a", "b"]);
    assert_eq!(
        db.execute(&ack_delete, rusqlite::params!["rcpt", "a"])
            .unwrap(),
        1
    );
    assert_eq!(listed(&db), ["b"]);
}

#[test]
fn the_held_read_is_covered_by_the_archive_index() {
    let db = migrated_db();
    let plan = plan_of(&db, &archive_held_sql(3), 3);
    assert!(
        plan.contains("COVERING INDEX idx_messages_archive"),
        "the held read walks no body: {plan}"
    );
}

// ---- the consumer's idempotence, on the real statements

#[test]
fn a_new_insert_is_listed_at_version_1() {
    let mut db = migrated_db();
    assert_eq!(
        apply(&mut db, &[insert("m1", 1, "hello")]),
        [Verdict::Apply]
    );
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 1, false)));
    assert_eq!(listed(&db), ["m1"]);
}

#[test]
fn a_repeated_message_is_a_no_op() {
    let mut db = migrated_db();
    apply(&mut db, &[insert("m1", 1, "hello")]);
    let before: String = db
        .query_row(
            "SELECT updated_at FROM messages WHERE message_id = 'm1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        apply(&mut db, &[insert("m1", 1, "hello")]),
        [Verdict::Repeat]
    );
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 1, false)));
    let n: i64 = db
        .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let after: String = db
        .query_row(
            "SELECT updated_at FROM messages WHERE message_id = 'm1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn an_older_version_never_moves_the_row_back() {
    let mut db = migrated_db();
    apply(&mut db, &[insert("m1", 1, "hello")]);
    apply(&mut db, &[ack("m1", 2, None)]);
    assert_eq!(
        apply(&mut db, &[insert("m1", 1, "hello")]),
        [Verdict::Repeat]
    );
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 2, true)));
    assert!(listed(&db).is_empty());
}

/// The upsert's own guard, under a race the plan did not see (two consumers
/// read the row at the same version): the older write changes nothing.
#[test]
fn the_upsert_guard_refuses_an_older_version_by_itself() {
    let db = migrated_db();
    let run = |m: &ArchiveMessage| {
        let mut n = 0;
        for (sql, params) in statements(m) {
            let params: Vec<Sql> = params.iter().map(to_sql).collect();
            n = db.execute(sql, rusqlite::params_from_iter(params)).unwrap();
        }
        n
    };
    assert_eq!(run(&ack("m1", 2, Some("hello"))), 1);
    assert_eq!(run(&insert("m1", 1, "hello")), 0, "older: no change");
    assert_eq!(run(&ack("m1", 2, Some("hello"))), 0, "the same: no change");
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 2, true)));
}

#[test]
fn a_newer_version_overwrites_and_moves_the_version_forward() {
    let mut db = migrated_db();
    apply(&mut db, &[insert("m1", 1, "hello")]);
    assert_eq!(
        apply(&mut db, &[insert("m1", 3, "hello again")]),
        [Verdict::Apply]
    );
    assert_eq!(row(&db, "m1"), Some(("hello again".into(), 3, false)));
}

#[test]
fn an_acknowledgment_after_its_insert_marks_the_row_and_no_listing_returns_it() {
    let mut db = migrated_db();
    apply(
        &mut db,
        &[insert("m1", 1, "hello"), insert("m2", 1, "there")],
    );
    assert_eq!(listed(&db), ["m1", "m2"]);
    assert_eq!(apply(&mut db, &[ack("m1", 2, None)]), [Verdict::Apply]);
    // The body the hub dropped after the insert was archived is kept here.
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 2, true)));
    assert_eq!(listed(&db), ["m2"]);
}

#[test]
fn an_acknowledgment_before_its_insert_stays_acknowledged_when_the_insert_arrives() {
    let mut db = migrated_db();
    // Without a body (the hub had archived nothing and kept no body to send):
    // an empty, acknowledged mark.
    assert_eq!(apply(&mut db, &[ack("m1", 2, None)]), [Verdict::Apply]);
    assert_eq!(row(&db, "m1"), Some((String::new(), 2, true)));
    assert!(listed(&db).is_empty());
    assert_eq!(
        apply(&mut db, &[insert("m1", 1, "hello")]),
        [Verdict::Repeat]
    );
    assert_eq!(row(&db, "m1"), Some((String::new(), 2, true)));
    assert!(listed(&db).is_empty());

    // With its body (a retained box's row never archived before): kept whole.
    assert_eq!(
        apply(&mut db, &[ack("m2", 2, Some("kept"))]),
        [Verdict::Apply]
    );
    assert_eq!(
        apply(&mut db, &[insert("m2", 1, "kept")]),
        [Verdict::Repeat]
    );
    assert_eq!(row(&db, "m2"), Some(("kept".into(), 2, true)));
    assert!(listed(&db).is_empty());
}

#[test]
fn an_insert_and_its_acknowledgment_in_one_batch_end_acknowledged_in_either_order() {
    for batch in [
        vec![insert("m1", 1, "hello"), ack("m1", 2, Some("hello"))],
        vec![ack("m1", 2, Some("hello")), insert("m1", 1, "hello")],
    ] {
        let mut db = migrated_db();
        let verdicts = apply(&mut db, &batch);
        assert_eq!(
            verdicts
                .iter()
                .filter(|v| **v == Verdict::Superseded)
                .count(),
            1
        );
        assert_eq!(row(&db, "m1"), Some(("hello".into(), 2, true)));
        assert!(listed(&db).is_empty());
    }
}

#[test]
fn another_recipients_row_under_the_same_id_is_never_touched() {
    let mut db = migrated_db();
    apply(&mut db, &[insert("m1", 1, "hello")]);
    let other = ArchiveMessage {
        recipient: "someone-else".into(),
        ..insert("m1", 5, "theirs")
    };
    assert_eq!(apply(&mut db, &[other]), [Verdict::Collision]);
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 1, false)));
    let r: String = db
        .query_row(
            "SELECT recipient FROM messages WHERE message_id = 'm1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(r, "rcpt");
}

#[test]
fn a_row_stored_by_the_d1_path_is_archived_over_at_version_1() {
    let mut db = migrated_db();
    db.execute(
        "INSERT INTO message_boxes (identity_key, type) VALUES ('rcpt', 'inbox')",
        [],
    )
    .unwrap();
    db.execute(
        INSERT_MESSAGE_SQL,
        rusqlite::params!["m1", 1, "sndr", "rcpt", "hello", None::<String>],
    )
    .unwrap();
    assert_eq!(apply(&mut db, &[ack("m1", 2, None)]), [Verdict::Apply]);
    assert_eq!(row(&db, "m1"), Some(("hello".into(), 2, true)));
}

// ---- the plan, pure

#[test]
fn the_plan_against_what_d1_holds() {
    let held: HashMap<String, Held> = [
        ("at1", "rcpt", 1),
        ("at2", "rcpt", 2),
        ("theirs", "someone-else", 1),
    ]
    .into_iter()
    .map(|(id, r, v)| {
        (
            id.to_string(),
            Held {
                recipient: r.into(),
                version: v,
            },
        )
    })
    .collect();
    let batch = [
        insert("new", 1, "b"),
        insert("at1", 1, "b"),
        ack("at1", 2, None),
        insert("at2", 1, "b"),
        ack("at2", 2, None),
        insert("theirs", 1, "b"),
        ack("new", 2, None),
    ];
    assert_eq!(
        plan(&batch, &held),
        [
            Verdict::Superseded,
            Verdict::Superseded,
            Verdict::Apply,
            Verdict::Superseded,
            Verdict::Repeat,
            Verdict::Collision,
            Verdict::Apply,
        ]
    );
}

#[test]
fn the_same_message_twice_in_one_batch_is_written_once() {
    let batch = [insert("m", 1, "b"), insert("m", 1, "b")];
    assert_eq!(
        plan(&batch, &HashMap::new()),
        [Verdict::Apply, Verdict::Superseded]
    );
}

// ---- the malformed-message rule

#[test]
fn a_well_formed_message_parses_and_unknown_fields_are_ignored() {
    let m = parse(serde_json::json!({
        "recipient": "rcpt", "messageId": "m1", "version": 1, "change": "insert",
        "messageBox": "inbox", "sender": "sndr", "body": "hello", "later": true
    }))
    .unwrap();
    assert_eq!(
        m,
        ArchiveMessage {
            created_at: None,
            ..insert("m1", 1, "hello")
        }
    );
    let a = parse(serde_json::json!({
        "recipient": "rcpt", "messageId": "m1", "version": 2, "change": "acknowledge",
        "messageBox": "inbox", "sender": "sndr"
    }))
    .unwrap();
    assert_eq!((a.change, a.body), (Change::Acknowledge, None));
}

#[test]
fn a_malformed_message_is_refused_with_its_reason() {
    let good = serde_json::json!({
        "recipient": "rcpt", "messageId": "m1", "version": 1, "change": "insert",
        "messageBox": "inbox", "sender": "sndr", "body": "hello"
    });
    let with = |k: &str, v: serde_json::Value| {
        let mut m = good.clone();
        m[k] = v;
        m
    };
    let without = |k: &str| {
        let mut m = good.clone();
        m.as_object_mut().unwrap().remove(k);
        m
    };
    for (bad, why) in [
        (serde_json::json!("a string"), "not an archive message"),
        (serde_json::json!(null), "not an archive message"),
        (with("version", serde_json::json!(0)), "version 0"),
        (
            with("version", serde_json::json!(-1)),
            "not an archive message",
        ),
        (
            with("version", serde_json::json!("1")),
            "not an archive message",
        ),
        (
            with("change", serde_json::json!("delete")),
            "not an archive message",
        ),
        (with("recipient", serde_json::json!("")), "empty recipient"),
        (with("messageId", serde_json::json!("")), "empty messageId"),
        (without("messageBox"), "not an archive message"),
        (without("sender"), "not an archive message"),
        (without("body"), "an insert without its body"),
    ] {
        let err = parse(bad.clone()).expect_err(&bad.to_string());
        assert!(err.contains(why), "{bad}: {err}");
    }
}

#[test]
fn every_applied_message_writes_its_box_then_its_row() {
    let [(box_sql, box_params), (row_sql, row_params)] = statements(&ack("m1", 2, None));
    assert_eq!((box_sql, box_params.len()), (ARCHIVE_BOX_SQL, 2));
    assert_eq!(row_sql, ARCHIVE_UPSERT_SQL);
    assert_eq!(row_params.len(), ARCHIVE_UPSERT_SQL.matches('?').count());
    assert!(
        matches!(row_params[3], QVal::Null),
        "no body: NULL, kept by COALESCE"
    );
    assert!(matches!(row_params[5], QVal::Int(1)), "an acknowledgment");
    assert!(matches!(row_params[6], QVal::Int(2)), "its version");
}

// ---- the template's queue blocks

/// The producer is bound under `ARCHIVE_QUEUE` and never sent to in this
/// release; the consumer's numbers are the design's (bsv-stack-lean
/// `docs/p0/mbx-hot-path-m28a.md`, section 6, R1).
#[test]
fn the_template_binds_the_queue_and_consumes_it_with_the_designs_numbers() {
    let toml = include_str!("../../wrangler.toml");
    let producer = "[[queues.producers]]\nbinding = \"ARCHIVE_QUEUE\"\nqueue = \"relay-archive\"\n";
    let consumer = "[[queues.consumers]]\nqueue = \"relay-archive\"\nmax_batch_size = 100\n\
                    max_batch_timeout = 2\nmax_retries = 3\nretry_delay = 10\n";
    assert!(toml.contains(producer));
    assert!(toml.contains(consumer));
    assert!(!toml.contains("dead_letter_queue"), "no dead-letter queue");
    let src = include_str!("../lib.rs");
    assert!(
        !src.contains("ARCHIVE_QUEUE\")")
            && !include_str!("../routes/send_message.rs").contains("ARCHIVE_QUEUE"),
        "neither the Worker's routes nor the D1 send path enqueue"
    );
    // 0.8.1: the mailbox hub alone enqueues, in one place.
    let hub = include_str!("../message_hub_sql.rs");
    assert_eq!(hub.matches("env.queue(\"ARCHIVE_QUEUE\")").count(), 1);
}

#[test]
fn the_held_read_refuses_a_schema_without_migration_0011() {
    let db = db_at_0_7_1();
    let Err(err) = db.prepare(&archive_held_sql(1)) else {
        panic!("no such index");
    };
    assert!(err.to_string().contains("idx_messages_archive"), "{err}");
}
