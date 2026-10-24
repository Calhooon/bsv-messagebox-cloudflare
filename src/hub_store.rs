//! The hub store's router (0.8.1, R2 of the relay mailbox).
//!
//! One var, `HUB_STORE`, read once per request, names where a hub id goes and
//! which store a send, a listing and an acknowledgment use (bsv-stack-lean
//! `docs/p0/mbx-hot-path-m28a.md`, section 6):
//!
//! - `kv` (the default, a missing var): today's paths, byte for byte. Hub ids
//!   go to `MESSAGE_HUB`; sends, listings and acknowledgments go through D1.
//!   No request reaches `MessageHubSql`.
//! - `sql`: hub ids go to `MESSAGE_HUB_SQL`; a send lands in the recipient
//!   hub's mailbox, a listing and an acknowledgment are the caller's hub's
//!   (`message_hub_sql`).
//! - `kv-drain`, the rollback of `sql`: hub ids go to `MESSAGE_HUB`, sends
//!   through D1 as `kv`, and every listing and acknowledgment also asks the
//!   identity's `MessageHubSql` for the rows it still holds, merged by id.
//!
//! Any other value refuses the boot: every request answers a typed 500 naming
//! the var, never a silent `kv`.

use serde_json::{json, Value};

/// The var's name.
pub const HUB_STORE_VAR: &str = "HUB_STORE";

/// The binding of the KV-backed hub class (`MessageHub`, migration `v3`).
pub const KV_HUB_BINDING: &str = "MESSAGE_HUB";

/// The binding of the SQLite-backed hub class (`MessageHubSql`, migration `v5`).
/// Named here alone: every hub id reaches it through `HubStore::hub_binding`,
/// and the archive consumer through `archive_hub_binding`.
pub const SQL_HUB_BINDING: &str = "MESSAGE_HUB_SQL";

/// The three values of `HUB_STORE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubStore {
    Kv,
    Sql,
    KvDrain,
}

/// Where a send, or a listing and an acknowledgment, are stored and read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePath {
    /// D1, as before R2.
    D1,
    /// The hub's mailbox (`MessageHubSql`), with the legacy merge of the rows
    /// D1 still holds for the box.
    Mailbox,
    /// D1, and the rows the identity's `MessageHubSql` still holds, merged by id.
    D1AndDrain,
}

impl HubStore {
    /// Read the var's value. `None` (no var) is `kv`; any value but the three
    /// is the refusal, carrying the value it read.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None | Some("kv") => Ok(HubStore::Kv),
            Some("sql") => Ok(HubStore::Sql),
            Some("kv-drain") => Ok(HubStore::KvDrain),
            Some(other) => Err(other.to_string()),
        }
    }

    /// The var as the Worker's environment holds it.
    pub fn from_env(env: &worker::Env) -> Result<Self, String> {
        let raw = env.var(HUB_STORE_VAR).ok().map(|v| v.to_string());
        Self::parse(raw.as_deref())
    }

    /// The binding every hub id goes to: the socket's hub, the push, the
    /// presence, the session lane's verify, the rejoin deadline.
    pub fn hub_binding(self) -> &'static str {
        match self {
            HubStore::Kv | HubStore::KvDrain => KV_HUB_BINDING,
            HubStore::Sql => SQL_HUB_BINDING,
        }
    }

    /// Where a send stores its rows.
    pub fn send_path(self) -> StorePath {
        match self {
            HubStore::Kv | HubStore::KvDrain => StorePath::D1,
            HubStore::Sql => StorePath::Mailbox,
        }
    }

    /// Where a listing reads and an acknowledgment writes.
    pub fn read_path(self) -> StorePath {
        match self {
            HubStore::Kv => StorePath::D1,
            HubStore::Sql => StorePath::Mailbox,
            HubStore::KvDrain => StorePath::D1AndDrain,
        }
    }

    /// Whether this request may reach `MessageHubSql` at all.
    #[cfg(test)]
    pub fn reaches_sql_class(self) -> bool {
        self.hub_binding() == SQL_HUB_BINDING
            || self.send_path() != StorePath::D1
            || self.read_path() != StorePath::D1
    }
}

/// The binding the archive consumer tells a row's archive is written
/// (`/internal/archive-done`): only `MessageHubSql` enqueues, so only it is told.
pub fn archive_hub_binding() -> &'static str {
    SQL_HUB_BINDING
}

/// The refused boot's answer: 500 `ERR_HUB_STORE_INVALID`, naming the var and
/// the value it read.
pub fn refused_boot_answer(value: &str) -> (Value, u16) {
    (
        json!({
            "status": "error",
            "code": "ERR_HUB_STORE_INVALID",
            "description": format!(
                "{HUB_STORE_VAR} is \"{value}\"; it must be kv, sql or kv-drain (unset is kv)"
            ),
        }),
        500,
    )
}

/// The hub namespace of this request's hub ids, by the router. A refused var
/// is an error, never `kv`.
pub fn hub_namespace(env: &worker::Env) -> worker::Result<worker::ObjectNamespace> {
    let store = HubStore::from_env(env)
        .map_err(|v| worker::Error::from(refused_boot_answer(&v).0["description"].to_string()))?;
    env.durable_object(store.hub_binding())
}

// -- The box switch (0.8.1; LOW's design 2026-10-23 section 2.4, the owner's word) --

/// The var naming the boxes whose sends are refused: a comma-separated list
/// of box names. A missing or empty var switches nothing off.
pub const BOXES_OFF_VAR: &str = "BOXES_OFF";

/// The box names a `BOXES_OFF` value lists (trimmed, empty entries dropped).
pub fn boxes_off(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether a send into `message_box` is switched off by a `BOXES_OFF` value.
pub fn box_is_off(raw: Option<&str>, message_box: &str) -> bool {
    boxes_off(raw).iter().any(|b| b == message_box)
}

/// The switch's refusal: 403 `ERR_BOX_OFF`, the box named.
pub fn box_off_answer(message_box: &str) -> (Value, u16) {
    (
        json!({
            "status": "error",
            "code": "ERR_BOX_OFF",
            "description": format!("box {message_box} is off"),
        }),
        403,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_var_is_kv_and_the_three_values_parse() {
        assert_eq!(HubStore::parse(None), Ok(HubStore::Kv));
        assert_eq!(HubStore::parse(Some("kv")), Ok(HubStore::Kv));
        assert_eq!(HubStore::parse(Some("sql")), Ok(HubStore::Sql));
        assert_eq!(HubStore::parse(Some("kv-drain")), Ok(HubStore::KvDrain));
    }

    #[test]
    fn any_other_value_is_refused_never_a_silent_kv() {
        for v in ["", "KV", "Sql", "kv_drain", "d1", " kv", "sqlite"] {
            assert_eq!(HubStore::parse(Some(v)), Err(v.to_string()), "{v:?}");
        }
        let (body, status) = refused_boot_answer("sqlite");
        assert_eq!(status, 500);
        assert_eq!(body["status"], "error");
        assert_eq!(body["code"], "ERR_HUB_STORE_INVALID");
        let d = body["description"].as_str().unwrap();
        assert!(d.contains("HUB_STORE") && d.contains("\"sqlite\""), "{d}");
    }

    #[test]
    fn each_value_routes_as_the_design_writes() {
        assert_eq!(HubStore::Kv.hub_binding(), "MESSAGE_HUB");
        assert_eq!(HubStore::Kv.send_path(), StorePath::D1);
        assert_eq!(HubStore::Kv.read_path(), StorePath::D1);

        assert_eq!(HubStore::Sql.hub_binding(), "MESSAGE_HUB_SQL");
        assert_eq!(HubStore::Sql.send_path(), StorePath::Mailbox);
        assert_eq!(HubStore::Sql.read_path(), StorePath::Mailbox);

        assert_eq!(HubStore::KvDrain.hub_binding(), "MESSAGE_HUB");
        assert_eq!(HubStore::KvDrain.send_path(), StorePath::D1);
        assert_eq!(HubStore::KvDrain.read_path(), StorePath::D1AndDrain);
    }

    /// The class's fetches one request of each path makes, as the dispatch
    /// takes them from the router: a send's context and insert per recipient
    /// on the mailbox path, a listing's or an acknowledgment's one hop off
    /// the D1 path, a presence read's one hop when hub ids go to the class.
    fn class_fetches(store: HubStore, recipients: usize) -> [(&'static str, usize); 4] {
        let send = if store.send_path() == StorePath::Mailbox {
            2 * recipients
        } else {
            0
        };
        let read = usize::from(store.read_path() != StorePath::D1);
        let presence = usize::from(store.hub_binding() == SQL_HUB_BINDING);
        [
            ("send", send),
            ("list", read),
            ("acknowledge", read),
            ("presence", presence),
        ]
    }

    // R2 under kv: no request reaches MessageHubSql. The count is zero on the
    // send, list, acknowledge and presence paths; the pins below hold the
    // dispatch to the router (every hub id through `hub_namespace`, every
    // mailbox call in an arm the router names), so the count is the code's.
    #[test]
    fn under_kv_the_class_counts_zero_fetches_on_every_path() {
        for (path, n) in class_fetches(HubStore::Kv, 3) {
            assert_eq!(n, 0, "{path} reaches MessageHubSql under kv");
        }
        assert_eq!(HubStore::parse(None), Ok(HubStore::Kv));
        let sql: usize = class_fetches(HubStore::Sql, 3).iter().map(|(_, n)| n).sum();
        assert_eq!(sql, 6 + 1 + 1 + 1);
        let drain: Vec<usize> = class_fetches(HubStore::KvDrain, 3)
            .iter()
            .map(|(_, n)| *n)
            .collect();
        assert_eq!(drain, [0, 1, 1, 0]);
    }

    /// The source up to its earliest test module.
    fn strip_tests(src: &str) -> &str {
        src.find("\n#[cfg(test)]\nmod ").map_or(src, |i| &src[..i])
    }

    #[test]
    fn every_hub_id_goes_through_the_router() {
        // EngineIoSession is not touched by R2 (the brief's rule): its three
        // forwards stay on MESSAGE_HUB, named in the report.
        for (name, src) in [
            ("lib.rs", include_str!("lib.rs")),
            ("message_hub.rs", include_str!("message_hub.rs")),
            ("socketio_worker.rs", include_str!("socketio_worker.rs")),
            (
                "routes/send_message.rs",
                include_str!("routes/send_message.rs"),
            ),
            ("archive.rs", include_str!("archive.rs")),
        ] {
            let code = strip_tests(src);
            assert!(
                !code.contains("durable_object(\"MESSAGE_HUB\")"),
                "{name} names MESSAGE_HUB outside the router"
            );
            assert!(
                !code.contains("\"MESSAGE_HUB_SQL\""),
                "{name} names MESSAGE_HUB_SQL outside the router"
            );
        }
        let lib = strip_tests(include_str!("lib.rs"));
        assert_eq!(lib.matches("crate::hub_store::hub_namespace(").count(), 6);
        let sql = strip_tests(include_str!("message_hub_sql.rs"));
        assert_eq!(
            sql.matches("SQL_HUB_BINDING").count(),
            1,
            "one helper, sql_hub"
        );
        let archive = strip_tests(include_str!("archive.rs"));
        assert!(!archive.contains("SQL_HUB_BINDING"));
        assert_eq!(archive.matches("archive_hub_binding()").count(), 2);
    }

    #[test]
    fn every_mailbox_call_sits_in_an_arm_the_router_names() {
        let lib = strip_tests(include_str!("lib.rs"));
        for (handler, next) in [
            ("async fn handle_list_messages(", "fn list_store_error("),
            (
                "async fn handle_acknowledge_message(",
                "/// The three honest answers",
            ),
        ] {
            let at = lib.find(handler).unwrap();
            let body = &lib[at..at + lib[at..].find(next).unwrap()];
            let d1 = body.find("StorePath::D1 =>").expect(handler);
            let d1_arm = &body[d1..d1 + body[d1..].find("StorePath::Mailbox =>").unwrap()];
            assert!(
                !d1_arm.contains("message_hub_sql::"),
                "{handler}: the D1 arm calls the class"
            );
            assert!(body.contains("HubStore::from_env(env)"), "{handler}");
        }
        let send = strip_tests(include_str!("routes/send_message.rs"));
        let at = send.find("pub async fn process_send(").unwrap();
        let body = &send[at..at + send[at..].find("pub(crate) async fn store_send<").unwrap()];
        assert_eq!(body.matches("MailboxSendStore {").count(), 1);
        let mailbox_arm = body.find("Ok(StorePath::Mailbox) =>").unwrap();
        assert!(body.find("MailboxSendStore {").unwrap() > mailbox_arm);
        // The presence read goes to the router's hub.
        let at = lib.find("async fn handle_presence_route(").unwrap();
        let body = &lib[at..at
            + lib[at..]
                .find("fn presence_invalid_room_response(")
                .unwrap()];
        assert!(body.contains("crate::hub_store::hub_namespace(env)"));
    }

    // The template's two R2 edits, and the two operator vars left out of it.
    #[test]
    fn the_template_binds_the_class_under_v5_and_sets_neither_var() {
        let toml = include_str!("../wrangler.toml");
        assert!(toml.contains(
            "[[durable_objects.bindings]]\nname = \"MESSAGE_HUB_SQL\"\nclass_name = \"MessageHubSql\"\n"
        ));
        assert!(toml
            .contains("[[migrations]]\ntag = \"v5\"\nnew_sqlite_classes = [\"MessageHubSql\"]\n"));
        // v1 to v4 unchanged, v5 after them, MessageHub still bound.
        let tags: Vec<usize> = ["\"v1\"", "\"v2\"", "\"v3\"", "\"v4\"", "\"v5\""]
            .iter()
            .map(|t| toml.find(&format!("tag = {t}")).expect(t))
            .collect();
        assert!(tags.windows(2).all(|w| w[0] < w[1]));
        assert!(toml.contains("name = \"MESSAGE_HUB\"\nclass_name = \"MessageHub\"\n"));
        for line in toml.lines() {
            let l = line.trim_start();
            assert!(
                !l.starts_with("HUB_STORE") && !l.starts_with("BOXES_OFF"),
                "the template sets no {l}"
            );
        }
    }

    #[test]
    fn only_kv_never_reaches_the_sql_class() {
        assert!(!HubStore::Kv.reaches_sql_class());
        assert!(HubStore::Sql.reaches_sql_class());
        assert!(HubStore::KvDrain.reaches_sql_class());
    }

    #[test]
    fn the_box_switch_lists_names_and_a_missing_var_switches_nothing_off() {
        assert!(boxes_off(None).is_empty());
        assert!(boxes_off(Some("")).is_empty());
        assert!(boxes_off(Some(" , ,")).is_empty());
        assert_eq!(
            boxes_off(Some("webrtc_signal, lane-knock ,,x")),
            vec!["webrtc_signal", "lane-knock", "x"]
        );
        assert!(!box_is_off(None, "webrtc_signal"));
        assert!(box_is_off(Some("a,webrtc_signal"), "webrtc_signal"));
        // A name, never a prefix or a pattern.
        assert!(!box_is_off(Some("webrtc"), "webrtc_signal"));
        assert!(!box_is_off(Some("webrtc_signal"), "webrtc"));
    }

    #[test]
    fn the_switch_answers_403_err_box_off_naming_the_box() {
        let (body, status) = box_off_answer("webrtc_signal");
        assert_eq!(status, 403);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "code": "ERR_BOX_OFF",
                "description": "box webrtc_signal is off",
            })
        );
    }
}
