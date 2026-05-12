//! Cloudflare Analytics GraphQL query for the MessageHub DurableObject
//! during the soak window.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

const GRAPHQL_URL: &str = "https://api.cloudflare.com/client/v4/graphql";

pub async fn query_do_metrics(
    token: &str,
    account_id: &str,
    namespace_id: &str,
    start_iso: &str,
    end_iso: &str,
) -> Result<Value> {
    let http = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let query = format!(
        "query {{ viewer {{ accounts(filter: {{accountTag: \"{account}\"}}) {{ \
durableObjectsPeriodicGroups(filter: {{datetimeMinute_geq: \"{start}\", datetimeMinute_leq: \"{end}\", namespaceId: \"{ns}\"}}, limit: 200, orderBy: [datetimeMinute_ASC]) {{ \
dimensions {{ datetimeMinute }} \
sum {{ activeTime cpuTime duration inboundWebsocketMsgCount outboundWebsocketMsgCount }} \
}} }} }} }}",
        account = account_id,
        ns = namespace_id,
        start = start_iso,
        end = end_iso
    );

    let body = json!({ "query": query });

    let resp = http
        .post(GRAPHQL_URL)
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .context("CF GraphQL POST")?;

    let status = resp.status();
    let text = resp.text().await.context("read CF GraphQL body")?;
    if !status.is_success() {
        return Err(anyhow!("CF GraphQL HTTP {status}: {text}"));
    }

    let v: Value = serde_json::from_str(&text).context("parse CF GraphQL JSON")?;
    Ok(v)
}
