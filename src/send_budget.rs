//! The per-identity send budget on `/sendMessage` (0.4.4, bsv-low #591 M3 and
//! NOTE-3): how many sends one identity makes in a window, and how many bytes
//! of message and payment text it hands the relay that no delivery fee
//! judged. Through 0.4.3 there was neither.
//!
//! The numbers are the relay's own 0.3.x bounds, stated in its CHANGELOG:
//! a window's sends are one listing of a box (`LIST_MESSAGES_LIMIT`, 100, the
//! bound `/listMessages` has had since 0.3.x), and a window's unjudged bytes
//! are one payment body of 0.3.28 (`MAX_PAYMENT_BODY_BYTES`, 4 MiB, the
//! reference's default body limit). The window is a minute. A deployment
//! sets its own with `SEND_BUDGET_SENDS`, `SEND_BUDGET_BYTES` and
//! `SEND_BUDGET_WINDOW_SECS`. A payment a delivery fee judges is not counted
//! in bytes: it is paid for, and a valid BEEF is never refused for its size.

use serde::Deserialize;
use serde_json::{json, Value};

type RouteResult = (Value, u16);

/// The window, in seconds.
pub const WINDOW_SECS: u64 = 60;
/// The sends one identity makes in a window: one listing of a box.
pub const SENDS: u64 = 100;
/// The bytes of unjudged text one identity sends in a window: one payment
/// body of 0.3.28.
pub const UNJUDGED_BYTES: u64 = 4 * 1024 * 1024;

/// One identity's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub window_secs: u64,
    pub sends: u64,
    pub bytes: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            window_secs: WINDOW_SECS,
            sends: SENDS,
            bytes: UNJUDGED_BYTES,
        }
    }
}

impl Budget {
    /// The deployment's numbers, each defaulting to the relay's own.
    pub fn from_env(env: &worker::Env) -> Self {
        let var = |name: &str| {
            env.var(name)
                .ok()
                .and_then(|v| v.to_string().trim().parse::<u64>().ok())
                .filter(|n| *n > 0)
        };
        let budget = Self::default();
        Self {
            window_secs: var("SEND_BUDGET_WINDOW_SECS").unwrap_or(budget.window_secs),
            sends: var("SEND_BUDGET_SENDS").unwrap_or(budget.sends),
            bytes: var("SEND_BUDGET_BYTES").unwrap_or(budget.bytes),
        }
    }

    /// The window `now` falls in: its start, in unix seconds.
    pub fn window_of(&self, now: u64) -> u64 {
        now - now % self.window_secs
    }
}

/// One send charged: `sends` sends and `bytes` bytes added to the window, and
/// what the window holds after.
pub const CHARGE_SQL: &str =
    "INSERT INTO send_budget (identity, window_start, sends, bytes) VALUES (?, ?, ?, ?) \
     ON CONFLICT(identity, window_start) DO UPDATE SET \
     sends = sends + excluded.sends, bytes = bytes + excluded.bytes \
     RETURNING sends, bytes";
/// The windows that have closed.
pub const FORGET_WINDOWS_SQL: &str = "DELETE FROM send_budget WHERE window_start < ?";

/// Where the windows are kept.
#[async_trait::async_trait(?Send)]
pub trait Windows {
    /// Add to the window and answer what it holds after: (sends, bytes).
    async fn charge(
        &self,
        identity: &str,
        window_start: u64,
        sends: u64,
        bytes: u64,
    ) -> Result<(u64, u64), String>;
}

/// Charge one send of `bytes` unjudged bytes to `identity` at `now`, and
/// refuse it when the window is spent: 429 `ERR_SEND_BUDGET`, naming the
/// window, what it holds, the bound and when the next opens. A store that
/// cannot answer refuses nothing: the budget guards the relay, it is no word
/// on the sender.
pub async fn charge(
    windows: &dyn Windows,
    budget: &Budget,
    identity: &str,
    now: u64,
    bytes: u64,
) -> Result<(), RouteResult> {
    let start = budget.window_of(now);
    let Ok((sends, held)) = windows.charge(identity, start, 1, bytes).await else {
        return Ok(());
    };
    let next = start + budget.window_secs;
    let refuse = |what: String| {
        Err((
            json!({
                "status": "error",
                "code": "ERR_SEND_BUDGET",
                "description": format!(
                    "{} in the window of {} s from {} (unix seconds); send again from {}.",
                    what, budget.window_secs, start, next
                ),
                "windowStart": start,
                "windowSecs": budget.window_secs,
                "retryAt": next,
            }),
            429,
        ))
    };
    if sends > budget.sends {
        return refuse(format!(
            "{} sends, and an identity makes at most {}",
            sends, budget.sends
        ));
    }
    if held > budget.bytes {
        return refuse(format!(
            "{} bytes of message and payment no delivery fee judges, and an identity sends at most {}",
            held, budget.bytes
        ));
    }
    Ok(())
}

/// The windows over D1.
pub struct D1Windows<'a> {
    pub db: &'a worker::D1Database,
}

#[derive(Debug, Deserialize)]
struct Held {
    sends: f64,
    bytes: f64,
}

#[async_trait::async_trait(?Send)]
impl Windows for D1Windows<'_> {
    async fn charge(
        &self,
        identity: &str,
        window_start: u64,
        sends: u64,
        bytes: u64,
    ) -> Result<(u64, u64), String> {
        let q = crate::d1::Query::new(CHARGE_SQL)
            .bind(identity)
            .bind(window_start)
            .bind(sends)
            .bind(bytes);
        let held: Option<Held> = q.fetch_optional(self.db).await.map_err(|e| e.to_string())?;
        let held = held.ok_or("the charge returned no row")?;
        Ok((held.sends as u64, held.bytes as u64))
    }
}

/// The windows that closed before `now`, gone: the scheduled event.
pub async fn forget_closed(db: &worker::D1Database, budget: &Budget, now: u64) {
    let q = crate::d1::Query::new(FORGET_WINDOWS_SQL).bind(budget.window_of(now));
    if let Err(e) = q.execute(db).await {
        worker::console_error!("AUDIT send_budget.forget FAILED: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// The windows on a real SQLite with the real migration and statement.
    struct Sqlite(RefCell<rusqlite::Connection>);

    impl Sqlite {
        fn new() -> Self {
            let db = rusqlite::Connection::open_in_memory().unwrap();
            db.execute_batch(include_str!("../migrations/0006_send_budget.sql"))
                .unwrap();
            Self(RefCell::new(db))
        }
    }

    #[async_trait::async_trait(?Send)]
    impl Windows for Sqlite {
        async fn charge(
            &self,
            identity: &str,
            window_start: u64,
            sends: u64,
            bytes: u64,
        ) -> Result<(u64, u64), String> {
            self.0
                .borrow()
                .query_row(
                    CHARGE_SQL,
                    rusqlite::params![identity, window_start, sends, bytes],
                    |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
                )
                .map_err(|e| e.to_string())
        }
    }

    const SENDER: &str = "02aa";
    const NOW: u64 = 1_790_000_030;

    #[tokio::test]
    async fn the_budget_refuses_the_101st_send_of_a_window_naming_the_window() {
        let windows = Sqlite::new();
        let budget = Budget::default();
        for _ in 0..SENDS {
            assert_eq!(charge(&windows, &budget, SENDER, NOW, 0).await, Ok(()));
        }
        let (body, status) = charge(&windows, &budget, SENDER, NOW, 0).await.unwrap_err();
        eprintln!("send_budget: {status} {}", body["description"]);
        assert_eq!((status, &body["code"]), (429, &json!("ERR_SEND_BUDGET")));
        assert_eq!(body["windowStart"], 1_789_999_980u64);
        assert_eq!(body["retryAt"], 1_790_000_040u64);
        let text = body["description"].as_str().unwrap();
        assert!(
            text.contains("101 sends") && text.contains("at most 100"),
            "{text}"
        );
        assert!(text.contains("window of 60 s from 1789999980"), "{text}");
        // Another identity, and the next window, are their own.
        assert_eq!(charge(&windows, &budget, "03bb", NOW, 0).await, Ok(()));
        assert_eq!(charge(&windows, &budget, SENDER, NOW + 60, 0).await, Ok(()));
    }

    #[tokio::test]
    async fn unjudged_bytes_past_the_window_are_refused_naming_them() {
        let windows = Sqlite::new();
        let budget = Budget::default();
        assert_eq!(
            charge(&windows, &budget, SENDER, NOW, 2_000_000).await,
            Ok(())
        );
        assert_eq!(
            charge(&windows, &budget, SENDER, NOW, 2_000_000).await,
            Ok(())
        );
        let (body, status) = charge(&windows, &budget, SENDER, NOW, 2_000_000)
            .await
            .unwrap_err();
        assert_eq!(status, 429);
        let text = body["description"].as_str().unwrap();
        assert!(
            text.contains("6000000 bytes") && text.contains("4194304"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_answer_refuses_nothing() {
        struct Down;
        #[async_trait::async_trait(?Send)]
        impl Windows for Down {
            async fn charge(&self, _: &str, _: u64, _: u64, _: u64) -> Result<(u64, u64), String> {
                Err("D1_ERROR: unavailable".to_string())
            }
        }
        assert_eq!(
            charge(&Down, &Budget::default(), SENDER, NOW, 0).await,
            Ok(())
        );
    }

    #[test]
    fn the_closed_windows_are_swept_by_a_seek() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../migrations/0006_send_budget.sql"))
            .unwrap();
        let plan: String = db
            .prepare(&format!("EXPLAIN QUERY PLAN {FORGET_WINDOWS_SQL}"))
            .unwrap()
            .query_map([1u64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(plan.contains("SEARCH send_budget"), "{plan}");
    }
}
