-- ============================================================
-- 멀티테넌트 쇼핑몰 스키마 (SQLite)
-- User(super_admin|admin|customer) → Tenant → Product/Order
-- ============================================================

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- 사용자 (플랫폼 전체)
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,          -- ULID
    username     TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'customer', -- super_admin | admin | customer
    display_name TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1,
    tenant_id    TEXT,                      -- admin/customer → 소속 테넌트, super_admin → NULL
    balance      INTEGER NOT NULL DEFAULT 0, -- 지갑 잔액(원)
    last_login_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at   DATETIME
);

-- 테넌트 (쇼핑몰 입점사)
CREATE TABLE IF NOT EXISTS tenants (
    id           TEXT PRIMARY KEY,
    name         TEXT UNIQUE NOT NULL,      -- 상점명
    slug         TEXT UNIQUE NOT NULL,      -- URL 식별자 (예: my-shop)
    domain       TEXT,                      -- 커스텀 접속 도메인 (예: myshop.example.com)
    owner_id     TEXT NOT NULL,             -- users.id (admin role)
    description  TEXT,
    logo_url     TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at   DATETIME,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- 테넌트 관리자 배정 (admin ↔ tenant 다대다: 한 admin이 여러 상점 관리)
CREATE TABLE IF NOT EXISTS tenant_admins (
    tenant_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (user_id)   REFERENCES users(id)
);

-- 상품
CREATE TABLE IF NOT EXISTS products (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT,
    price        INTEGER NOT NULL DEFAULT 0, -- 원 단위
    stock        INTEGER NOT NULL DEFAULT 0,
    category     TEXT,
    image_url    TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at   DATETIME,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 주문
CREATE TABLE IF NOT EXISTS orders (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    customer_id  TEXT NOT NULL,             -- users.id
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|paid|shipped|cancelled
    total_amount INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id)   REFERENCES tenants(id),
    FOREIGN KEY (customer_id) REFERENCES users(id)
);

-- 주문 항목
CREATE TABLE IF NOT EXISTS order_items (
    id          TEXT PRIMARY KEY,
    order_id    TEXT NOT NULL,
    product_id  TEXT NOT NULL,
    quantity    INTEGER NOT NULL DEFAULT 1,
    unit_price  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (order_id)   REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Refresh 토큰 (SHA-256 해시 저장, rotation)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    token_hash  TEXT UNIQUE NOT NULL,
    expires_at  DATETIME NOT NULL,
    revoked_at  DATETIME,
    replaced_by TEXT,
    user_agent  TEXT,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 회원가입 요청 (customer 셀프 가입 → admin 승인/반려)
CREATE TABLE IF NOT EXISTS signup_requests (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT,
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    reject_reason TEXT,
    reviewed_by   TEXT,                            -- 처리한 admin users.id
    reviewed_at   DATETIME,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 잔액 충전 요청 (customer → admin 승인 시 users.balance 증가)
CREATE TABLE IF NOT EXISTS charge_requests (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    username      TEXT,                            -- 표시용(비정규화)
    amount        INTEGER NOT NULL,                -- 충전 요청 금액(원)
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    reject_reason TEXT,
    reviewed_by   TEXT,                            -- 처리한 admin users.id
    reviewed_at   DATETIME,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (user_id)   REFERENCES users(id)
);

-- [AIR] 방어 토글 플래그 (key=방어식별자, enabled=ON/OFF; 미존재=OFF=취약)
CREATE TABLE IF NOT EXISTS defense_flags (
    flag_key   TEXT PRIMARY KEY,
    enabled    INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- [AIR] 보안 인시던트 (공격 탐지·대응 기록)
CREATE TABLE IF NOT EXISTS security_incidents (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,          -- ORDER_NEGATIVE_QTY 등
    endpoint     TEXT,
    client_ip    TEXT,
    actor        TEXT,
    payload      TEXT,                   -- 탐지된 요청 본문(잘림)
    action_taken TEXT,                   -- DEFENSE_ENABLED:order.qty-guard 등
    status       TEXT NOT NULL DEFAULT 'DETECTED', -- DETECTED|MITIGATED|PATCHED|FAILED
    severity     TEXT,                   -- CRITICAL|HIGH|MEDIUM|LOW (탐지 시점 위험도, 영속) [A2]
    score        INTEGER,                -- 0~100 위험 점수(탐지 시점, 영속) [A2]
    created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- 감사 로그
CREATE TABLE IF NOT EXISTS audit_logs (
    id             TEXT PRIMARY KEY,
    actor_id       TEXT,
    actor_username TEXT,
    tenant_id      TEXT,
    action         TEXT NOT NULL,
    resource_type  TEXT,
    resource_id    TEXT,
    detail         TEXT,
    ip_address     TEXT,
    created_at     DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_users_tenant        ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_products_tenant     ON products(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orders_tenant       ON orders(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orders_customer     ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user        ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor         ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant        ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_signup_tenant_status ON signup_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_tenant_admins_user   ON tenant_admins(user_id);
CREATE INDEX IF NOT EXISTS idx_charge_tenant_status  ON charge_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_charge_user           ON charge_requests(user_id);
-- [A1] 보안 인시던트 조회/집계 최적화 (findRecent 정렬 · IP/유형 이력 질의)
CREATE INDEX IF NOT EXISTS idx_incident_created      ON security_incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incident_client_ip    ON security_incidents(client_ip);
CREATE INDEX IF NOT EXISTS idx_incident_type         ON security_incidents(type);
