use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::handle_cors_preflight, process_auth, sign_json_response, AuthMiddlewareOptions,
        AuthResult,
    },
};
use serde_json::json;
use worker::*;

mod api_docs;
mod d1;
mod error;
mod routes;
mod storage;
mod types;
mod validation;

mod beef_upload;
mod devices;
mod fcm;
mod fcm_cache;
mod fcm_jwt;
mod fcm_token;
mod payments;
mod permissions;
mod r2_presign;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    init_panic_hook();

    // CORS preflight — must respond before auth
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    // OpenAPI spec — public endpoint (no auth required)
    if req.path() == "/api-docs" && req.method() == Method::Get {
        let spec = api_docs::openapi_spec();
        let response = Response::from_json(&spec)?;
        return Ok(add_cors_headers(response));
    }

    // --- BRC-31 auth for all other routes ---
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| Error::from(format!("SERVER_PRIVATE_KEY not set: {}", e)))?
        .to_string();

    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key,
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

    let (auth_context, req, session, request_body) = match auth_result {
        AuthResult::Authenticated {
            context,
            request,
            session,
            body,
        } => (context, request, session, body),
        // Pass middleware responses through unchanged. The middleware's 401
        // for unauthenticated requests emits
        // `{status:"error", code:"UNAUTHORIZED", message:"Mutual-authentication failed!"}`
        // which matches the TS reference server at messagebox.babbage.systems
        // byte-for-byte (verified via tests/e2e_live_parity.py).
        AuthResult::Response(response) => return Ok(response),
    };

    let identity_key = &auth_context.identity_key;
    let db = env.d1("DB")?;
    let store = storage::Storage::new(&db);

    // Dispatch authenticated routes
    let path = req.path();
    let method = req.method();
    let (body, status) = match (method, path.as_str()) {
        // /health behind auth matches TS and Go ("all routes require auth").
        // Authed GET /health returns 200; unauthed requests are rejected by
        // the BRC-31 middleware with UNAUTHORIZED + "Mutual-authentication failed!".
        (Method::Get, "/") | (Method::Get, "/health") => (
            json!({ "status": "success", "message": "bsv-messagebox-cloudflare is running" }),
            200,
        ),
        (Method::Post, "/sendMessage") => {
            handle_send_message(&request_body, identity_key, &env, &store).await
        }
        (Method::Post, "/listMessages") => {
            handle_list_messages(&request_body, identity_key, &store).await
        }
        (Method::Post, "/acknowledgeMessage") => {
            handle_acknowledge_message(&request_body, identity_key, &store).await
        }

        (Method::Post, "/permissions/set") => {
            permissions::handle_set(&request_body, identity_key, &store).await
        }
        (Method::Get, "/permissions/get") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_get(&url, identity_key, &store).await
        }
        (Method::Get, "/permissions/list") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_list(&url, identity_key, &store).await
        }
        (Method::Get, "/permissions/quote") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_quote(&url, identity_key, &store).await
        }

        (Method::Post, "/registerDevice") => {
            devices::handle_register_device(&request_body, identity_key, &store).await
        }
        (Method::Get, "/devices") => devices::handle_list_devices(identity_key, &store).await,

        (Method::Post, "/beef/upload-url") => {
            beef_upload::handle_upload_url(identity_key, &env).await
        }

        _ => (
            json!({ "status": "error", "code": "ERR_NOT_FOUND", "description": "Not Found" }),
            404,
        ),
    };

    // Sign response if session available, otherwise plain CORS
    match session {
        Some(ref s) => {
            sign_json_response(&body, status, &[], s).map_err(|e| Error::from(e.to_string()))
        }
        None => {
            let resp = Response::from_json(&body)?.with_status(status);
            Ok(add_cors_headers(resp))
        }
    }
}

// -- Route handlers --

async fn handle_send_message(
    raw_body: &[u8],
    sender_key: &str,
    env: &Env,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_send_message(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Evaluate fees for all recipients
    let mut blocked = Vec::new();
    let mut fee_map: Vec<(String, String, i32)> = Vec::new(); // (recipient, messageId, fee)

    for (recipient, message_id) in &validated.recipients {
        let fee = match store
            .get_recipient_fee(recipient, sender_key, &validated.message_box)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                return (
                    json!({
                        "status": "error", "code": "ERR_INTERNAL",
                        "description": format!("An internal error has occurred: {}", e)
                    }),
                    500,
                )
            }
        };

        if fee < 0 {
            blocked.push(recipient.clone());
        } else {
            fee_map.push((recipient.clone(), message_id.clone(), fee));
        }
    }

    if !blocked.is_empty() {
        return (
            json!({
                "status": "error",
                "code": "ERR_DELIVERY_BLOCKED",
                "description": format!("Blocked recipients: {}", blocked.join(", ")),
                "blockedRecipients": blocked
            }),
            403,
        );
    }

    // Check if payment is required
    let delivery_fee: i32 = store
        .get_server_delivery_fee(&validated.message_box)
        .await
        .unwrap_or_default();
    let any_recipient_fee = fee_map.iter().any(|(_, _, f)| *f > 0);
    let requires_payment = delivery_fee > 0 || any_recipient_fee;

    // Payment processing. If payment.beefR2Key is set, resolve the BEEF
    // from R2 and rewrite the payment's `tx` with the fetched bytes. The
    // r2_cleanup_key is deleted after the message is successfully stored.
    let (per_recipient_outputs, r2_cleanup_key, resolved_payment) = if requires_payment {
        match &validated.payment {
            None => {
                return (
                    json!({
                        "status": "error", "code": "ERR_MISSING_PAYMENT_TX",
                        "description": "Payment transaction data is required for payable delivery."
                    }),
                    400,
                )
            }
            Some(payment) => {
                let (resolved, cleanup) =
                    match beef_upload::resolve_r2_backed_payment(payment, sender_key, env).await {
                        Ok(pair) => pair,
                        Err(e) => return e,
                    };

                match payments::process_payment(&resolved, &fee_map, delivery_fee, sender_key, env)
                    .await
                {
                    Ok(outputs) => (outputs, cleanup, Some(resolved)),
                    Err(e) => return e,
                }
            }
        }
    } else {
        (std::collections::HashMap::new(), None, None)
    };

    // Insert messages for each recipient
    let mut results = Vec::new();
    for (recipient, message_id, _fee) in &fee_map {
        // Auto-create message box
        let box_id = match store
            .get_or_create_message_box(recipient, &validated.message_box)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                return (
                    json!({
                        "status": "error", "code": "ERR_INTERNAL",
                        "description": format!("An internal error has occurred: {}", e)
                    }),
                    500,
                )
            }
        };

        // Build stored body: {"message": body, "payment": ...}.
        // Use the R2-resolved payment (if any) so the stored BEEF is inline,
        // not a reference to an object that will be deleted shortly.
        let per_payment = per_recipient_outputs.get(recipient.as_str());
        let stored_body = match per_payment {
            Some(payment_data) => {
                let mut p = resolved_payment
                    .clone()
                    .or_else(|| validated.payment.clone())
                    .unwrap_or(json!({}));
                if let Some(obj) = p.as_object_mut() {
                    obj.insert("outputs".to_string(), payment_data.clone());
                }
                json!({ "message": validated.body, "payment": p }).to_string()
            }
            None => json!({ "message": validated.body }).to_string(),
        };

        // Insert (dedup on messageId)
        match store
            .insert_message(message_id, box_id, sender_key, recipient, &stored_body)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return (
                    json!({
                        "status": "error",
                        "code": "ERR_DUPLICATE_MESSAGE",
                        "description": "Duplicate message."
                    }),
                    400,
                );
            }
            Err(e) => {
                return (
                    json!({
                        "status": "error", "code": "ERR_INTERNAL",
                        "description": format!("An internal error has occurred: {}", e)
                    }),
                    500,
                )
            }
        }

        results.push(json!({
            "recipient": recipient,
            "messageId": message_id
        }));

        // Fire-and-forget FCM push for notifications box
        if fcm::should_use_fcm_delivery(&validated.message_box) {
            let _ =
                fcm::send_fcm_notification(recipient, message_id, "New Message", env, store).await;
        }
    }

    // Best-effort cleanup of the R2-uploaded BEEF now that all recipients
    // have their messages stored. If the delete fails the object will expire
    // via R2's own lifecycle rules (or the operator can purge manually).
    if let Some(key) = r2_cleanup_key {
        let _ = beef_upload::delete_beef_from_r2(env, &key).await;
    }

    (
        json!({
            "status": "success",
            "message": format!("Your message has been sent to {} recipient(s).", results.len()),
            "results": results
        }),
        200,
    )
}

async fn handle_list_messages(
    raw_body: &[u8],
    identity_key: &str,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_list_messages(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let messages = match store
        .list_messages(identity_key, &validated.message_box)
        .await
    {
        Ok(m) => m,
        Err(_e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL_ERROR",
                    "description": "An internal error has occurred while listing messages."
                }),
                500,
            )
        }
    };

    // Format response — camelCase, body as raw string, timestamps as ISO 8601 for Node parity
    let formatted: Vec<serde_json::Value> = messages
        .iter()
        .map(|row| {
            json!({
                "messageId": row.message_id.as_deref().unwrap_or(""),
                "body": row.body.as_deref().unwrap_or(""),
                "sender": row.sender.as_deref().unwrap_or(""),
                "createdAt": storage::to_iso8601(row.created_at.as_deref()),
                "updatedAt": storage::to_iso8601(row.updated_at.as_deref()),
            })
        })
        .collect();

    (json!({ "status": "success", "messages": formatted }), 200)
}

async fn handle_acknowledge_message(
    raw_body: &[u8],
    identity_key: &str,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_acknowledge(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let deleted = match store
        .acknowledge_messages(identity_key, &validated.message_ids)
        .await
    {
        Ok(n) => n,
        Err(_e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL_ERROR",
                    "description": "An internal error has occurred while acknowledging the message"
                }),
                500,
            )
        }
    };

    if deleted == 0 {
        return (
            json!({
                "status": "error",
                "code": "ERR_INVALID_ACKNOWLEDGMENT",
                "description": "Message not found!"
            }),
            400,
        );
    }

    (json!({ "status": "success" }), 200)
}

// Auth-layer error responses (`{code:"UNAUTHORIZED", message:"..."}`) are
// emitted by bsv-middleware-cloudflare directly, matching the TS reference
// server at messagebox.babbage.systems byte-for-byte. No per-path rewriter
// needed — 11/12 live-parity tests against that server pass identical.
