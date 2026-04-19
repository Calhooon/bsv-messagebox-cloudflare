// OpenAPI 3.0 specification for the bsv-messagebox-cloudflare API.
// Served at GET /api-docs as a public endpoint (no auth required).
//
// The spec is assembled from helper functions to avoid exceeding the
// `json!` macro recursion limit that a single giant literal would hit.

use serde_json::{json, Value};

/// Returns the complete OpenAPI 3.0 spec as a `serde_json::Value`.
pub fn openapi_spec() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": info(),
        "servers": [{ "url": "/", "description": "Current deployment" }],
        "components": components(),
        "paths": paths(),
        "tags": tags()
    })
}

fn info() -> Value {
    json!({
        "title": "bsv-messagebox-cloudflare",
        "description": "BSV message box service — authenticated message delivery with permissions, payments, and device registration. All authenticated endpoints use BRC-31 mutual authentication. For payloads ≤100 MB this server is byte-for-byte compatible with the TS `message-box-server` and Go `go-messagebox-server` reference implementations; above 100 MB it exposes an opt-in Rust-only R2 upload extension (see `POST /beef/upload-url`).",
        "version": "0.1.0",
        "license": { "name": "Proprietary" }
    })
}

fn tags() -> Value {
    json!([
        { "name": "Health", "description": "Service health endpoints." },
        { "name": "Messages", "description": "Message sending, listing, and acknowledgment." },
        { "name": "Permissions", "description": "Delivery permission and fee management." },
        { "name": "Devices", "description": "FCM device registration for push notifications." }
    ])
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

fn components() -> Value {
    json!({
        "securitySchemes": {
            "BRC31Auth": {
                "type": "http",
                "scheme": "bearer",
                "description": "BRC-31 mutual authentication. The client must present a signed request envelope; the server validates the identity key and returns a signed response."
            }
        },
        "schemas": schemas()
    })
}

fn schemas() -> Value {
    let mut m = serde_json::Map::new();
    m.insert("ErrorResponse".into(), schema_error_response());
    m.insert("SendMessageRequest".into(), schema_send_message_request());
    m.insert("MessagePayload".into(), schema_message_payload());
    m.insert("PaymentPayload".into(), schema_payment_payload());
    m.insert("PaymentOutput".into(), schema_payment_output());
    m.insert("SendMessageResponse".into(), schema_send_message_response());
    m.insert("ListMessagesRequest".into(), schema_list_messages_request());
    m.insert(
        "ListMessagesResponse".into(),
        schema_list_messages_response(),
    );
    m.insert("MessageRow".into(), schema_message_row());
    m.insert("AcknowledgeRequest".into(), schema_acknowledge_request());
    m.insert("AcknowledgeResponse".into(), schema_acknowledge_response());
    m.insert(
        "SetPermissionRequest".into(),
        schema_set_permission_request(),
    );
    m.insert(
        "SetPermissionResponse".into(),
        schema_set_permission_response(),
    );
    m.insert("PermissionRow".into(), schema_permission_row());
    m.insert(
        "GetPermissionResponse".into(),
        schema_get_permission_response(),
    );
    m.insert(
        "ListPermissionsResponse".into(),
        schema_list_permissions_response(),
    );
    m.insert("QuoteSingleResponse".into(), schema_quote_single_response());
    m.insert("QuoteMultiResponse".into(), schema_quote_multi_response());
    m.insert(
        "RegisterDeviceRequest".into(),
        schema_register_device_request(),
    );
    m.insert(
        "RegisterDeviceResponse".into(),
        schema_register_device_response(),
    );
    m.insert("ListDevicesResponse".into(), schema_list_devices_response());
    m.insert("DeviceRow".into(), schema_device_row());
    m.insert("HealthResponse".into(), schema_health_response());
    Value::Object(m)
}

fn schema_error_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "code", "description"],
        "properties": {
            "status": { "type": "string", "enum": ["error"], "example": "error" },
            "code": { "type": "string", "description": "Machine-readable error code (e.g. ERR_MESSAGE_REQUIRED).", "example": "ERR_INVALID_REQUEST" },
            "description": { "type": "string", "description": "Human-readable error description.", "example": "An error occurred." }
        }
    })
}

fn schema_send_message_request() -> Value {
    json!({
        "type": "object",
        "required": ["message"],
        "properties": {
            "message": { "$ref": "#/components/schemas/MessagePayload" },
            "payment": { "$ref": "#/components/schemas/PaymentPayload" }
        }
    })
}

fn schema_message_payload() -> Value {
    json!({
        "type": "object",
        "required": ["messageBox", "body", "messageId"],
        "properties": {
            "recipient": {
                "description": "Single recipient public key or array of recipient public keys (compressed secp256k1, 66 hex chars). Mutually exclusive with `recipients`.",
                "oneOf": [
                    { "type": "string", "pattern": "^(02|03)[0-9a-fA-F]{64}$" },
                    { "type": "array", "items": { "type": "string", "pattern": "^(02|03)[0-9a-fA-F]{64}$" } }
                ]
            },
            "recipients": {
                "type": "array",
                "description": "Array of recipient public keys. Mutually exclusive with `recipient`.",
                "items": { "type": "string", "pattern": "^(02|03)[0-9a-fA-F]{64}$" }
            },
            "messageBox": { "type": "string", "description": "Name of the message box (e.g. \"inbox\", \"payment_inbox\", \"notifications\").", "example": "payment_inbox" },
            "messageId": {
                "description": "Unique message ID or array of IDs (one per recipient, same order).",
                "oneOf": [
                    { "type": "string" },
                    { "type": "array", "items": { "type": "string" } }
                ]
            },
            "body": {
                "description": "Message body — must be a non-empty string or JSON object.",
                "oneOf": [
                    { "type": "string", "minLength": 1 },
                    { "type": "object" }
                ]
            }
        }
    })
}

fn schema_payment_payload() -> Value {
    json!({
        "type": "object",
        "description": "Payment transaction data required when delivery or recipient fees apply.",
        "properties": {
            "tx": { "description": "Transaction data (BEEF hex string or object)." },
            "outputs": { "type": "array", "description": "Array of payment output descriptors.", "items": { "$ref": "#/components/schemas/PaymentOutput" } },
            "description": { "type": "string", "description": "Optional description of the payment." },
            "labels": { "type": "array", "items": { "type": "string" }, "description": "Optional labels for the payment." },
            "seekPermission": { "type": "boolean", "description": "Whether to request permission from the recipient." }
        }
    })
}

fn schema_payment_output() -> Value {
    json!({
        "type": "object",
        "required": ["outputIndex", "protocol"],
        "properties": {
            "outputIndex": { "type": "integer", "description": "Index of the transaction output." },
            "protocol": { "type": "string", "description": "Payment protocol identifier (e.g. \"wallet payment\")." },
            "paymentRemittance": { "description": "Optional payment remittance data." },
            "insertionRemittance": { "description": "Optional insertion remittance data." },
            "customInstructions": { "description": "Optional custom instructions." }
        }
    })
}

fn schema_send_message_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "message", "results"],
        "properties": {
            "status": { "type": "string", "enum": ["success"], "example": "success" },
            "message": { "type": "string", "description": "Human-readable summary.", "example": "Your message has been sent to 1 recipient(s)." },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "recipient": { "type": "string", "description": "Recipient public key." },
                        "messageId": { "type": "string", "description": "The message ID assigned to this delivery." }
                    }
                }
            }
        }
    })
}

fn schema_list_messages_request() -> Value {
    json!({
        "type": "object",
        "required": ["messageBox"],
        "properties": {
            "messageBox": { "type": "string", "description": "Name of the message box to list.", "example": "payment_inbox" }
        }
    })
}

fn schema_list_messages_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "messages"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "messages": { "type": "array", "items": { "$ref": "#/components/schemas/MessageRow" } }
        }
    })
}

fn schema_message_row() -> Value {
    json!({
        "type": "object",
        "properties": {
            "messageId": { "type": "string", "description": "Unique message identifier." },
            "body": { "type": "string", "description": "Raw message body (JSON string)." },
            "sender": { "type": "string", "description": "Sender public key." },
            "createdAt": { "type": "string", "description": "ISO 8601 creation timestamp." },
            "updatedAt": { "type": "string", "description": "ISO 8601 last-updated timestamp." }
        }
    })
}

fn schema_acknowledge_request() -> Value {
    json!({
        "type": "object",
        "required": ["messageIds"],
        "properties": {
            "messageIds": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Array of message IDs to acknowledge (delete)." }
        }
    })
}

fn schema_acknowledge_response() -> Value {
    json!({
        "type": "object",
        "required": ["status"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] }
        }
    })
}

fn schema_set_permission_request() -> Value {
    json!({
        "type": "object",
        "required": ["messageBox", "recipientFee"],
        "properties": {
            "sender": { "type": "string", "description": "Sender public key (compressed secp256k1, 66 hex chars). Omit for box-wide default.", "pattern": "^(02|03)[0-9a-fA-F]{64}$" },
            "messageBox": { "type": "string", "description": "Message box name.", "example": "inbox" },
            "recipientFee": { "type": "integer", "description": "Fee in satoshis. -1 = blocked, 0 = always allow, >0 = payment required.", "example": 0 }
        }
    })
}

fn schema_set_permission_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "description"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "description": { "type": "string", "description": "Human-readable description of the permission change.", "example": "Box-wide default for all senders to inbox is now always allowed." }
        }
    })
}

fn schema_permission_row() -> Value {
    json!({
        "type": "object",
        "properties": {
            "sender": { "type": "string", "nullable": true, "description": "Sender public key, or null for box-wide default." },
            "messageBox": { "type": "string", "description": "Message box name." },
            "recipientFee": { "type": "integer", "description": "Fee in satoshis (-1, 0, or positive)." },
            "status": { "type": "string", "enum": ["blocked", "always_allow", "payment_required"], "description": "Human-readable status derived from recipientFee." },
            "createdAt": { "type": "string", "description": "ISO 8601 creation timestamp." },
            "updatedAt": { "type": "string", "description": "ISO 8601 last-updated timestamp." }
        }
    })
}

fn schema_get_permission_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "description"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "description": { "type": "string", "description": "Human-readable description." },
            "permission": {
                "nullable": true,
                "description": "The permission record, or null if none found.",
                "oneOf": [
                    { "$ref": "#/components/schemas/PermissionRow" },
                    { "type": "null" }
                ]
            }
        }
    })
}

fn schema_list_permissions_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "permissions", "totalCount"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "permissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "sender": { "type": "string", "nullable": true },
                        "messageBox": { "type": "string" },
                        "recipientFee": { "type": "integer" },
                        "createdAt": { "type": "string" },
                        "updatedAt": { "type": "string" }
                    }
                }
            },
            "totalCount": { "type": "integer", "description": "Total number of permissions matching the filter." }
        }
    })
}

fn schema_quote_single_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "description", "quote"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "description": { "type": "string", "example": "Message delivery quote generated." },
            "quote": {
                "type": "object",
                "properties": {
                    "deliveryFee": { "type": "integer", "description": "Server delivery fee in satoshis." },
                    "recipientFee": { "type": "integer", "description": "Recipient fee in satoshis (-1 = blocked, 0 = free, >0 = payment required)." }
                }
            }
        }
    })
}

fn schema_quote_multi_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "description", "quotesByRecipient", "totals", "blockedRecipients"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "description": { "type": "string", "example": "Message delivery quotes generated for 3 recipients." },
            "quotesByRecipient": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "recipient": { "type": "string" },
                        "messageBox": { "type": "string" },
                        "deliveryFee": { "type": "integer" },
                        "recipientFee": { "type": "integer" },
                        "status": { "type": "string", "enum": ["blocked", "always_allow", "payment_required"] }
                    }
                }
            },
            "totals": {
                "type": "object",
                "properties": {
                    "deliveryFees": { "type": "integer" },
                    "recipientFees": { "type": "integer" },
                    "totalForPayableRecipients": { "type": "integer" }
                }
            },
            "blockedRecipients": { "type": "array", "items": { "type": "string" } }
        }
    })
}

fn schema_register_device_request() -> Value {
    json!({
        "type": "object",
        "required": ["fcmToken"],
        "properties": {
            "fcmToken": { "type": "string", "minLength": 1, "description": "Firebase Cloud Messaging device token." },
            "deviceId": { "type": "string", "description": "Optional client-assigned device identifier." },
            "platform": { "type": "string", "enum": ["ios", "android", "web"], "description": "Device platform." }
        }
    })
}

fn schema_register_device_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "message", "deviceId"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "message": { "type": "string", "example": "Device registered successfully for push notifications" },
            "deviceId": { "type": "integer", "description": "Server-assigned device row ID." }
        }
    })
}

fn schema_list_devices_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "devices"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "devices": { "type": "array", "items": { "$ref": "#/components/schemas/DeviceRow" } }
        }
    })
}

fn schema_device_row() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "integer", "description": "Server-assigned device ID." },
            "deviceId": { "type": "string", "nullable": true, "description": "Client-assigned device identifier." },
            "platform": { "type": "string", "nullable": true, "description": "Device platform (ios, android, web)." },
            "fcmToken": { "type": "string", "description": "Truncated FCM token (last 10 characters prefixed with '...')." },
            "active": { "type": "boolean", "description": "Whether the device registration is active." },
            "createdAt": { "type": "string", "description": "ISO 8601 creation timestamp." },
            "updatedAt": { "type": "string", "description": "ISO 8601 last-updated timestamp." },
            "lastUsed": { "type": "string", "nullable": true, "description": "ISO 8601 timestamp of last push notification sent to this device." }
        }
    })
}

fn schema_health_response() -> Value {
    json!({
        "type": "object",
        "required": ["status", "message"],
        "properties": {
            "status": { "type": "string", "enum": ["success"] },
            "message": { "type": "string", "example": "bsv-messagebox-cloudflare is running" }
        }
    })
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn paths() -> Value {
    let mut m = serde_json::Map::new();
    m.insert("/health".into(), path_health());
    m.insert("/sendMessage".into(), path_send_message());
    m.insert("/listMessages".into(), path_list_messages());
    m.insert("/acknowledgeMessage".into(), path_acknowledge_message());
    m.insert("/permissions/set".into(), path_permissions_set());
    m.insert("/permissions/get".into(), path_permissions_get());
    m.insert("/permissions/list".into(), path_permissions_list());
    m.insert("/permissions/quote".into(), path_permissions_quote());
    m.insert("/registerDevice".into(), path_register_device());
    m.insert("/devices".into(), path_devices());
    m.insert("/beef/upload-url".into(), path_beef_upload_url());
    Value::Object(m)
}

fn path_beef_upload_url() -> Value {
    json!({
        "post": {
            "summary": "[RUST-ONLY EXTENSION] Presigned R2 URL for BEEFs >100 MB",
            "description": "**Not available on TS or Go reference servers.** Cloudflare Workers cap request bodies at 100 MB; the TS and Go ports have no equivalent cap. To handle larger BEEF payloads, this Rust server exposes an opt-in extension: call `/beef/upload-url` to receive a presigned R2 PUT URL, upload the BEEF bytes directly to R2 (up to 5 TB), then POST `/sendMessage` with `payment.beefR2Key = <key>` instead of `payment.tx`. Clients that stay under 100 MB should continue to use the inline `payment.tx` flow for universal compatibility across TS, Go, and Rust servers.",
            "operationId": "beefUploadUrl",
            "tags": ["Messages"],
            "security": [{ "BRC31Auth": [] }],
            "responses": {
                "200": {
                    "description": "Presigned URL valid for 10 minutes. Upload with `PUT` and a `Content-Type` of `application/octet-stream`; the key must then be passed back in `sendMessage.payment.beefR2Key`.",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["status", "url", "key", "expiresAt"],
                                "properties": {
                                    "status": { "type": "string", "enum": ["success"] },
                                    "url": { "type": "string", "description": "Presigned R2 PUT URL (S3 v4 signed)." },
                                    "key": { "type": "string", "description": "R2 object key scoped to the caller's identity key." },
                                    "expiresAt": { "type": "integer", "description": "Unix timestamp (seconds) at which the presigned URL expires." }
                                }
                            }
                        }
                    }
                },
                "500": {
                    "description": "R2 not configured on this deployment (R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY / R2_BUCKET_NAME missing).",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
                }
            }
        }
    })
}

fn path_health() -> Value {
    json!({
        "get": {
            "summary": "Health check",
            "description": "Returns a simple status indicating the service is running. Requires BRC-31 authentication, matching the TS and Go reference servers which protect every route.",
            "operationId": "healthCheck",
            "tags": ["Health"],
            "security": [{ "BRC31Auth": [] }],
            "responses": {
                "200": {
                    "description": "Service is healthy.",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } }
                },
                "401": {
                    "description": "Authentication required.",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
                }
            }
        }
    })
}

fn path_send_message() -> Value {
    json!({
        "post": {
            "summary": "Send message to one or more recipients",
            "description": "Delivers a message to one or more recipients' message boxes. Supports multi-recipient delivery with per-recipient message IDs. If any recipient has a fee configured, a payment transaction must be included. Blocked recipients cause the entire request to fail with ERR_DELIVERY_BLOCKED.",
            "operationId": "sendMessage",
            "tags": ["Messages"],
            "security": [{ "BRC31Auth": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SendMessageRequest" } } }
            },
            "responses": send_message_responses()
        }
    })
}

fn send_message_responses() -> Value {
    json!({
        "200": {
            "description": "Message(s) delivered successfully.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SendMessageResponse" } } }
        },
        "400": {
            "description": "Validation error (missing fields, invalid recipient key, messageId count mismatch, duplicate message, missing payment).",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingMessage": { "value": { "status": "error", "code": "ERR_MESSAGE_REQUIRED", "description": "Please provide a valid message to send!" } },
                    "invalidRecipient": { "value": { "status": "error", "code": "ERR_INVALID_RECIPIENT_KEY", "description": "Invalid recipient key: not-a-key" } },
                    "messageIdMismatch": { "value": { "status": "error", "code": "ERR_MESSAGEID_COUNT_MISMATCH", "description": "Provided 1 messageId for 2 recipients. Provide one messageId per recipient (same order)." } },
                    "duplicateMessage": { "value": { "status": "error", "code": "ERR_DUPLICATE_MESSAGE", "description": "Duplicate message." } },
                    "missingPayment": { "value": { "status": "error", "code": "ERR_MISSING_PAYMENT_TX", "description": "Payment transaction data is required for payable delivery." } }
                }
            }}
        },
        "403": {
            "description": "One or more recipients have blocked the sender.",
            "content": { "application/json": {
                "schema": {
                    "allOf": [
                        { "$ref": "#/components/schemas/ErrorResponse" },
                        { "type": "object", "properties": { "blockedRecipients": { "type": "array", "items": { "type": "string" } } } }
                    ]
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_list_messages() -> Value {
    json!({
        "post": {
            "summary": "List messages in a message box",
            "description": "Lists all messages in the authenticated user's specified message box. The identity key is derived from the BRC-31 auth context.",
            "operationId": "listMessages",
            "tags": ["Messages"],
            "security": [{ "BRC31Auth": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ListMessagesRequest" } } }
            },
            "responses": list_messages_responses()
        }
    })
}

fn list_messages_responses() -> Value {
    json!({
        "200": {
            "description": "Messages listed successfully. Returns an empty array if the message box does not exist or has no messages.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ListMessagesResponse" } } }
        },
        "400": {
            "description": "Validation error (missing or invalid messageBox).",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingBox": { "value": { "status": "error", "code": "ERR_MESSAGEBOX_REQUIRED", "description": "Please provide the name of a valid MessageBox!" } },
                    "invalidBox": { "value": { "status": "error", "code": "ERR_INVALID_MESSAGEBOX", "description": "MessageBox name must be a string!" } }
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_acknowledge_message() -> Value {
    json!({
        "post": {
            "summary": "Acknowledge (delete) messages",
            "description": "Deletes one or more messages by their IDs from the authenticated user's mailbox. Only messages where the authenticated user is the recipient can be acknowledged.",
            "operationId": "acknowledgeMessage",
            "tags": ["Messages"],
            "security": [{ "BRC31Auth": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AcknowledgeRequest" } } }
            },
            "responses": acknowledge_responses()
        }
    })
}

fn acknowledge_responses() -> Value {
    json!({
        "200": {
            "description": "Message(s) acknowledged successfully.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/AcknowledgeResponse" } } }
        },
        "400": {
            "description": "Validation error or message not found.",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingIds": { "value": { "status": "error", "code": "ERR_MESSAGE_ID_REQUIRED", "description": "Please provide the IDs of messages to acknowledge." } },
                    "invalidFormat": { "value": { "status": "error", "code": "ERR_INVALID_MESSAGE_ID", "description": "Message IDs must be formatted as an array of strings!" } },
                    "notFound": { "value": { "status": "error", "code": "ERR_INVALID_ACKNOWLEDGMENT", "description": "Message not found!" } }
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_permissions_set() -> Value {
    json!({
        "post": {
            "summary": "Set message permission",
            "description": "Sets a delivery permission for the authenticated user's message box. Controls who can send messages and at what cost. If `sender` is omitted, sets the box-wide default for all senders. A recipientFee of -1 blocks delivery, 0 allows free delivery, and a positive value requires payment in satoshis.",
            "operationId": "setPermission",
            "tags": ["Permissions"],
            "security": [{ "BRC31Auth": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetPermissionRequest" } } }
            },
            "responses": permissions_set_responses()
        }
    })
}

fn permissions_set_responses() -> Value {
    json!({
        "200": {
            "description": "Permission set successfully.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetPermissionResponse" } } }
        },
        "400": {
            "description": "Validation error (missing fields, invalid public key, invalid fee).",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingFields": { "value": { "status": "error", "code": "ERR_INVALID_REQUEST", "description": "messageBox (string) and recipientFee (number) are required. sender (string) is optional for box-wide settings." } },
                    "invalidKey": { "value": { "status": "error", "code": "ERR_INVALID_PUBLIC_KEY", "description": "Invalid sender public key format." } },
                    "invalidFee": { "value": { "status": "error", "code": "ERR_INVALID_FEE_VALUE", "description": "recipientFee must be an integer (-1, 0, or positive number)." } }
                }
            }}
        },
        "500": {
            "description": "Database error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_permissions_get() -> Value {
    json!({
        "get": {
            "summary": "Get permission for sender/box",
            "description": "Retrieves the delivery permission for a specific sender (or box-wide default if sender is omitted) to the authenticated user's message box. Returns null for the permission field if no permission record exists.",
            "operationId": "getPermission",
            "tags": ["Permissions"],
            "security": [{ "BRC31Auth": [] }],
            "parameters": [
                { "name": "messageBox", "in": "query", "required": true, "description": "Message box name.", "schema": { "type": "string" } },
                { "name": "sender", "in": "query", "required": false, "description": "Sender public key (compressed secp256k1). Omit to query the box-wide default.", "schema": { "type": "string" } }
            ],
            "responses": permissions_get_responses()
        }
    })
}

fn permissions_get_responses() -> Value {
    json!({
        "200": {
            "description": "Permission retrieved (may be null if none set).",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/GetPermissionResponse" } } }
        },
        "400": {
            "description": "Missing or invalid parameters.",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingBox": { "value": { "status": "error", "code": "ERR_MISSING_PARAMETERS", "description": "messageBox parameter is required." } },
                    "invalidKey": { "value": { "status": "error", "code": "ERR_INVALID_PUBLIC_KEY", "description": "Invalid sender public key format." } }
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_permissions_list() -> Value {
    json!({
        "get": {
            "summary": "List permissions with pagination",
            "description": "Lists all delivery permissions for the authenticated user with optional filtering by message box. Supports pagination via limit/offset and sort order on created_at.",
            "operationId": "listPermissions",
            "tags": ["Permissions"],
            "security": [{ "BRC31Auth": [] }],
            "parameters": permissions_list_params(),
            "responses": permissions_list_responses()
        }
    })
}

fn permissions_list_params() -> Value {
    json!([
        { "name": "messageBox", "in": "query", "required": false, "description": "Optional filter by message box name.", "schema": { "type": "string" } },
        { "name": "limit", "in": "query", "required": false, "description": "Maximum number of results to return (1-1000, default 100).", "schema": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 100 } },
        { "name": "offset", "in": "query", "required": false, "description": "Number of results to skip (default 0).", "schema": { "type": "integer", "minimum": 0, "default": 0 } },
        { "name": "createdAtOrder", "in": "query", "required": false, "description": "Sort order for created_at (default \"desc\").", "schema": { "type": "string", "enum": ["asc", "desc"], "default": "desc" } }
    ])
}

fn permissions_list_responses() -> Value {
    json!({
        "200": {
            "description": "Permissions listed successfully.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ListPermissionsResponse" } } }
        },
        "400": {
            "description": "Invalid pagination parameters.",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "invalidLimit": { "value": { "status": "error", "code": "ERR_INVALID_LIMIT", "description": "Limit must be a number between 1 and 1000" } },
                    "invalidOffset": { "value": { "status": "error", "code": "ERR_INVALID_OFFSET", "description": "Offset must be a non-negative number" } }
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_permissions_quote() -> Value {
    json!({
        "get": {
            "summary": "Get delivery pricing",
            "description": "Generates a delivery fee quote for sending to one or more recipients in a given message box. For a single recipient, returns a simple quote object. For multiple recipients, returns per-recipient breakdowns with totals and blocked-recipient information. The authenticated user is the sender.",
            "operationId": "quotePermission",
            "tags": ["Permissions"],
            "security": [{ "BRC31Auth": [] }],
            "parameters": [
                { "name": "messageBox", "in": "query", "required": true, "description": "Message box name.", "schema": { "type": "string" } },
                { "name": "recipient", "in": "query", "required": true, "description": "Recipient public key(s). Repeat for multiple recipients (e.g. ?recipient=02abc...&recipient=03def...).", "schema": { "type": "string" } }
            ],
            "responses": permissions_quote_responses()
        }
    })
}

fn permissions_quote_responses() -> Value {
    json!({
        "200": {
            "description": "Quote generated. Response shape depends on number of recipients.",
            "content": { "application/json": {
                "schema": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/QuoteSingleResponse" },
                        { "$ref": "#/components/schemas/QuoteMultiResponse" }
                    ]
                }
            }}
        },
        "400": {
            "description": "Missing or invalid parameters.",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "missingParams": { "value": { "status": "error", "code": "ERR_MISSING_PARAMETERS", "description": "recipient and messageBox parameters are required." } },
                    "invalidKey": { "value": { "status": "error", "code": "ERR_INVALID_PUBLIC_KEY", "description": "Invalid recipient public key at index(es): 0." } }
                }
            }}
        },
        "500": {
            "description": "Internal server error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_register_device() -> Value {
    json!({
        "post": {
            "summary": "Register FCM device",
            "description": "Registers or updates a device for Firebase Cloud Messaging push notifications. Uses UPSERT semantics — if the FCM token already exists for this user, the record is replaced.",
            "operationId": "registerDevice",
            "tags": ["Devices"],
            "security": [{ "BRC31Auth": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RegisterDeviceRequest" } } }
            },
            "responses": register_device_responses()
        }
    })
}

fn register_device_responses() -> Value {
    json!({
        "200": {
            "description": "Device registered successfully.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RegisterDeviceResponse" } } }
        },
        "400": {
            "description": "Validation error (invalid FCM token or platform).",
            "content": { "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" },
                "examples": {
                    "invalidToken": { "value": { "status": "error", "code": "ERR_INVALID_FCM_TOKEN", "description": "fcmToken must be a non-empty string." } },
                    "invalidPlatform": { "value": { "status": "error", "code": "ERR_INVALID_PLATFORM", "description": "platform must be one of: ios, android, web" } }
                }
            }}
        },
        "500": {
            "description": "Database error.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
        }
    })
}

fn path_devices() -> Value {
    json!({
        "get": {
            "summary": "List registered devices",
            "description": "Lists all FCM device registrations for the authenticated user. FCM tokens are truncated in the response (last 10 characters with '...' prefix).",
            "operationId": "listDevices",
            "tags": ["Devices"],
            "security": [{ "BRC31Auth": [] }],
            "responses": {
                "200": {
                    "description": "Devices listed successfully.",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ListDevicesResponse" } } }
                },
                "500": {
                    "description": "Database error.",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorResponse" } } }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_is_valid_json() {
        let spec = openapi_spec();
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "bsv-messagebox-cloudflare");
    }

    #[test]
    fn spec_has_all_paths() {
        let spec = openapi_spec();
        let paths = spec["paths"].as_object().unwrap();
        let expected = vec![
            "/health",
            "/sendMessage",
            "/listMessages",
            "/acknowledgeMessage",
            "/permissions/set",
            "/permissions/get",
            "/permissions/list",
            "/permissions/quote",
            "/registerDevice",
            "/devices",
            "/beef/upload-url",
        ];
        for path in &expected {
            assert!(paths.contains_key(*path), "Missing path: {}", path);
        }
        assert_eq!(paths.len(), expected.len());
    }

    #[test]
    fn spec_health_is_authenticated() {
        let spec = openapi_spec();
        let health = &spec["paths"]["/health"]["get"];
        // /health is behind BRC-31 auth, matching TS and Go reference servers.
        assert!(health.get("security").is_some());
    }

    #[test]
    fn spec_authenticated_endpoints_have_security() {
        let spec = openapi_spec();
        let auth_paths = vec![
            ("/sendMessage", "post"),
            ("/listMessages", "post"),
            ("/acknowledgeMessage", "post"),
            ("/permissions/set", "post"),
            ("/permissions/get", "get"),
            ("/permissions/list", "get"),
            ("/permissions/quote", "get"),
            ("/registerDevice", "post"),
            ("/devices", "get"),
            ("/beef/upload-url", "post"),
        ];
        for (path, method) in auth_paths {
            let endpoint = &spec["paths"][path][method];
            assert!(
                endpoint.get("security").is_some(),
                "Missing security on {} {}",
                method.to_uppercase(),
                path
            );
        }
    }

    #[test]
    fn spec_components_has_security_scheme() {
        let spec = openapi_spec();
        assert!(spec["components"]["securitySchemes"]["BRC31Auth"].is_object());
    }

    #[test]
    fn spec_all_endpoints_have_responses() {
        let spec = openapi_spec();
        let paths = spec["paths"].as_object().unwrap();
        for (path, methods) in paths {
            let methods_obj = methods.as_object().unwrap();
            for (method, endpoint) in methods_obj {
                assert!(
                    endpoint.get("responses").is_some(),
                    "Missing responses on {} {}",
                    method.to_uppercase(),
                    path
                );
            }
        }
    }

    #[test]
    fn spec_post_endpoints_have_request_body() {
        let spec = openapi_spec();
        let post_paths = vec![
            "/sendMessage",
            "/listMessages",
            "/acknowledgeMessage",
            "/permissions/set",
            "/registerDevice",
        ];
        for path in post_paths {
            let endpoint = &spec["paths"][path]["post"];
            assert!(
                endpoint.get("requestBody").is_some(),
                "Missing requestBody on POST {}",
                path
            );
        }
    }

    #[test]
    fn spec_get_endpoints_with_params_have_parameters() {
        let spec = openapi_spec();
        let get_param_paths = vec![
            "/permissions/get",
            "/permissions/list",
            "/permissions/quote",
        ];
        for path in get_param_paths {
            let endpoint = &spec["paths"][path]["get"];
            assert!(
                endpoint.get("parameters").is_some(),
                "Missing parameters on GET {}",
                path
            );
        }
    }
}
