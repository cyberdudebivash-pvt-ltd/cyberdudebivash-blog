-- SENTINEL APEX — Premium Intelligence Commerce Engine v1
-- Additive Cloudflare D1 schema for certified report catalog, Razorpay orders,
-- customer entitlements, and download audit. No legacy Redis billing tables are
-- modified; subscription/manual billing remain independent.

CREATE TABLE IF NOT EXISTS premium_report_catalog (
  report_id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  report_type TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  certification_state TEXT NOT NULL CHECK (certification_state = 'PREMIUM_CERTIFIED'),
  artifact_sha256 TEXT NOT NULL CHECK (length(artifact_sha256) = 64),
  artifact_key TEXT NOT NULL UNIQUE,
  artifact_filename TEXT NOT NULL,
  artifact_content_type TEXT NOT NULL DEFAULT 'text/markdown; charset=utf-8',
  artifact_size_bytes INTEGER NOT NULL CHECK (artifact_size_bytes > 0),
  price_minor INTEGER NOT NULL CHECK (price_minor > 0),
  currency TEXT NOT NULL CHECK (length(currency) = 3),
  status TEXT NOT NULL DEFAULT 'SELLABLE' CHECK (status IN ('SELLABLE', 'PAUSED', 'RETIRED')),
  reviewer_identity TEXT NOT NULL,
  review_timestamp TEXT NOT NULL,
  published_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_premium_report_catalog_status_published
  ON premium_report_catalog(status, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_premium_report_catalog_type_published
  ON premium_report_catalog(report_type, published_at DESC);

CREATE TABLE IF NOT EXISTS premium_orders (
  order_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  email TEXT NOT NULL,
  report_id TEXT NOT NULL,
  report_title TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL CHECK (length(artifact_sha256) = 64),
  artifact_key TEXT NOT NULL,
  artifact_filename TEXT NOT NULL,
  artifact_content_type TEXT NOT NULL,
  artifact_size_bytes INTEGER NOT NULL CHECK (artifact_size_bytes > 0),
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  currency TEXT NOT NULL CHECK (length(currency) = 3),
  razorpay_order_id TEXT NOT NULL UNIQUE,
  razorpay_payment_id TEXT UNIQUE,
  state TEXT NOT NULL DEFAULT 'ORDER_CREATED'
    CHECK (state IN ('ORDER_CREATED', 'PAYMENT_VERIFIED', 'ENTITLED', 'REFUNDED', 'CANCELLED')),
  created_at TEXT NOT NULL,
  verified_at TEXT,
  entitled_at TEXT,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (report_id) REFERENCES premium_report_catalog(report_id)
);

CREATE INDEX IF NOT EXISTS idx_premium_orders_owner_created
  ON premium_orders(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_premium_orders_report_created
  ON premium_orders(report_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_premium_orders_state_updated
  ON premium_orders(state, updated_at DESC);

CREATE TABLE IF NOT EXISTS premium_entitlements (
  entitlement_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  report_id TEXT NOT NULL,
  order_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'REFUNDED')),
  granted_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (owner_id, report_id),
  FOREIGN KEY (report_id) REFERENCES premium_report_catalog(report_id),
  FOREIGN KEY (order_id) REFERENCES premium_orders(order_id)
);

CREATE INDEX IF NOT EXISTS idx_premium_entitlements_owner_status
  ON premium_entitlements(owner_id, status, granted_at DESC);

CREATE TABLE IF NOT EXISTS premium_download_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT NOT NULL,
  report_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  downloaded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_premium_download_audit_owner_time
  ON premium_download_audit(owner_id, downloaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_premium_download_audit_report_time
  ON premium_download_audit(report_id, downloaded_at DESC);
