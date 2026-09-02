-- rust-message-box: D1 schema
-- Ported from message-box-server MySQL (5 migrations consolidated)

-- Message boxes: one per (identityKey, type) pair
CREATE TABLE IF NOT EXISTS message_boxes (
    message_box_id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(type, identity_key)
);

CREATE INDEX idx_message_boxes_identity ON message_boxes(identity_key);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT NOT NULL UNIQUE,
    message_box_id INTEGER NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (message_box_id) REFERENCES message_boxes(message_box_id) ON DELETE CASCADE
);

CREATE INDEX idx_messages_box ON messages(message_box_id);
CREATE INDEX idx_messages_recipient ON messages(recipient);
CREATE INDEX idx_messages_sender ON messages(sender);

-- Permissions: per-sender per-box, or box-wide default (sender IS NULL)
-- recipient_fee: -1 = blocked, 0 = allow free, >0 = satoshis required
CREATE TABLE IF NOT EXISTS message_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT,
    message_box TEXT NOT NULL,
    recipient_fee INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(recipient, sender, message_box)
);

CREATE INDEX idx_perms_recipient ON message_permissions(recipient);
CREATE INDEX idx_perms_recipient_box ON message_permissions(recipient, message_box);
CREATE INDEX idx_perms_box ON message_permissions(message_box);
CREATE INDEX idx_perms_sender ON message_permissions(sender);

-- Server delivery fees per message box type
CREATE TABLE IF NOT EXISTS server_fees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_box TEXT NOT NULL UNIQUE,
    delivery_fee INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed default server fees
-- 100 sats ≈ $0.000015 at $15/BSV. Covers Cloudflare Workers costs at modest
-- volume while staying imperceptibly cheap to end users. Operators can tune:
--   UPDATE server_fees SET delivery_fee = N WHERE message_box = 'notifications';
INSERT OR IGNORE INTO server_fees (message_box, delivery_fee) VALUES ('notifications', 100);
INSERT OR IGNORE INTO server_fees (message_box, delivery_fee) VALUES ('inbox', 0);
INSERT OR IGNORE INTO server_fees (message_box, delivery_fee) VALUES ('payment_inbox', 0);

-- Device registrations for FCM push notifications
CREATE TABLE IF NOT EXISTS device_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_key TEXT NOT NULL,
    fcm_token TEXT NOT NULL UNIQUE,
    device_id TEXT,
    platform TEXT,
    last_used TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_devices_identity ON device_registrations(identity_key);
CREATE INDEX idx_devices_identity_active ON device_registrations(identity_key, active);
CREATE INDEX idx_devices_last_used ON device_registrations(last_used);
