// DTOs describing the request/response shapes. Handlers currently dispatch on
// raw serde_json::Value for flexibility; the typed structs here document the
// wire format and are kept as future refactor targets.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ---------- Request types ----------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub message: MessagePayload,
    pub payment: Option<PaymentPayload>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePayload {
    /// Single recipient or array of recipients
    #[serde(default)]
    pub recipient: Option<StringOrVec>,
    #[serde(default)]
    pub recipients: Option<Vec<String>>,
    pub message_box: String,
    pub message_id: Option<StringOrVec>,
    pub body: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrVec {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s],
            Self::Multiple(v) => v,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub tx: serde_json::Value,
    pub outputs: Vec<PaymentOutput>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    #[serde(default)]
    pub seek_permission: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentOutput {
    pub output_index: u32,
    pub protocol: String,
    #[serde(default)]
    pub payment_remittance: Option<serde_json::Value>,
    #[serde(default)]
    pub insertion_remittance: Option<serde_json::Value>,
    #[serde(default)]
    pub custom_instructions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesRequest {
    pub message_box: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeRequest {
    pub message_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub fcm_token: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPermissionRequest {
    #[serde(default)]
    pub sender: Option<String>,
    pub message_box: String,
    pub recipient_fee: i32,
}

// ---------- Response types ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResult {
    pub recipient: String,
    pub message_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRow {
    pub message_id: String,
    pub body: serde_json::Value,
    pub sender: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRow {
    pub id: i64,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub fcm_token: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRow {
    pub sender: Option<String>,
    pub message_box: String,
    pub recipient_fee: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    pub delivery_fee: i32,
    pub recipient_fee: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiQuoteEntry {
    pub recipient: String,
    pub message_box: String,
    pub delivery_fee: i32,
    pub recipient_fee: i32,
    pub status: String,
}
