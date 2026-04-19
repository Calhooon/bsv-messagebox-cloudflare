// D1 query builder — borrowed from rust-chaintracks / rust-wallet-infra.
// D1 uses JsValue bindings, not sqlx. This provides type-safe parameterized queries.

use serde::de::DeserializeOwned;
use wasm_bindgen::JsValue;
use worker::D1Database;

/// Metadata returned from write operations (INSERT/UPDATE/DELETE).
pub struct ExecMeta {
    pub last_row_id: i64,
    pub changes: usize,
}

/// Type-safe parameter value for D1 binding.
pub enum QVal {
    Int(i64),
    Text(String),
    Bool(bool),
    Float(f64),
    Null,
}

impl From<i32> for QVal {
    fn from(v: i32) -> Self {
        QVal::Int(v as i64)
    }
}
impl From<u32> for QVal {
    fn from(v: u32) -> Self {
        QVal::Int(v as i64)
    }
}
impl From<i64> for QVal {
    fn from(v: i64) -> Self {
        QVal::Int(v)
    }
}
impl From<u64> for QVal {
    fn from(v: u64) -> Self {
        QVal::Int(v as i64)
    }
}
impl From<&str> for QVal {
    fn from(v: &str) -> Self {
        QVal::Text(v.to_string())
    }
}
impl From<String> for QVal {
    fn from(v: String) -> Self {
        QVal::Text(v)
    }
}
impl From<bool> for QVal {
    fn from(v: bool) -> Self {
        QVal::Bool(v)
    }
}
impl From<f64> for QVal {
    fn from(v: f64) -> Self {
        QVal::Float(v)
    }
}
impl<T: Into<QVal>> From<Option<T>> for QVal {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(val) => val.into(),
            None => QVal::Null,
        }
    }
}

impl QVal {
    pub fn to_js(&self) -> JsValue {
        match self {
            QVal::Int(v) => JsValue::from_f64(*v as f64),
            QVal::Text(v) => JsValue::from_str(v),
            QVal::Bool(v) => JsValue::from_bool(*v),
            QVal::Float(v) => JsValue::from_f64(*v),
            QVal::Null => JsValue::NULL,
        }
    }
}

/// Parameterized D1 query builder.
pub struct Query {
    sql: String,
    params: Vec<QVal>,
}

impl Query {
    pub fn new(sql: &str) -> Self {
        Self {
            sql: sql.to_string(),
            params: Vec::new(),
        }
    }

    pub fn bind(mut self, val: impl Into<QVal>) -> Self {
        self.params.push(val.into());
        self
    }

    /// Fetch all rows, deserialized into T.
    pub async fn fetch_all<T: DeserializeOwned>(&self, db: &D1Database) -> worker::Result<Vec<T>> {
        let stmt = db.prepare(&self.sql);
        let js_params: Vec<JsValue> = self.params.iter().map(|p| p.to_js()).collect();
        let stmt = stmt.bind(&js_params)?;
        let result = stmt.all().await?;
        result.results()
    }

    /// Fetch first row, deserialized into T.
    pub async fn fetch_optional<T: DeserializeOwned>(
        &self,
        db: &D1Database,
    ) -> worker::Result<Option<T>> {
        let stmt = db.prepare(&self.sql);
        let js_params: Vec<JsValue> = self.params.iter().map(|p| p.to_js()).collect();
        let stmt = stmt.bind(&js_params)?;
        stmt.first::<T>(None).await
    }

    /// Execute a write statement (INSERT, UPDATE, DELETE). Returns metadata.
    pub async fn execute(&self, db: &D1Database) -> worker::Result<ExecMeta> {
        let stmt = db.prepare(&self.sql);
        let js_params: Vec<JsValue> = self.params.iter().map(|p| p.to_js()).collect();
        let stmt = stmt.bind(&js_params)?;
        let result = stmt.run().await?;
        let meta = result.meta()?;
        Ok(ExecMeta {
            last_row_id: meta.as_ref().and_then(|m| m.last_row_id).unwrap_or(0) as i64,
            changes: meta.as_ref().and_then(|m| m.changes).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qval_conversions() {
        assert!(matches!(QVal::from(42_i32), QVal::Int(42)));
        assert!(matches!(QVal::from(42_u32), QVal::Int(42)));
        assert!(matches!(QVal::from(100_i64), QVal::Int(100)));
        assert!(matches!(QVal::from("hello"), QVal::Text(_)));
        assert!(matches!(QVal::from(String::from("hi")), QVal::Text(_)));
        assert!(matches!(QVal::from(true), QVal::Bool(true)));
        assert!(matches!(QVal::from(3.14_f64), QVal::Float(_)));
        assert!(matches!(QVal::from(None::<i32>), QVal::Null));
        assert!(matches!(QVal::from(Some(42_i32)), QVal::Int(42)));
    }

    #[test]
    fn query_builder_bind_chain() {
        let q = Query::new("SELECT * FROM t WHERE a = ? AND b = ? AND c = ?")
            .bind(1_i32)
            .bind("test")
            .bind(None::<String>);
        assert_eq!(q.params.len(), 3);
        assert_eq!(q.sql, "SELECT * FROM t WHERE a = ? AND b = ? AND c = ?");
        assert!(matches!(q.params[0], QVal::Int(1)));
        assert!(matches!(&q.params[1], QVal::Text(s) if s == "test"));
        assert!(matches!(q.params[2], QVal::Null));
    }
}
