"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const dataDirectory = path.join(__dirname, "data");
fs.mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
const databasePath = process.env.JUSTICE_DB_PATH
  ? path.resolve(process.env.JUSTICE_DB_PATH)
  : path.join(dataDirectory, "justice.sqlite");
fs.mkdirSync(path.dirname(databasePath), { recursive: true, mode: 0o700 });
const database = new DatabaseSync(databasePath);

database.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'police', 'prosecution', 'court', 'corrections')),
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

  CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL,
    offence_category TEXT NOT NULL,
    station TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('Police intake', 'Prosecutor review', 'Court proceedings', 'Correctional custody', 'Closed')),
    closed_by_role TEXT CHECK (closed_by_role IN ('police', 'prosecution', 'court', 'corrections')),
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS cases_stage_idx ON cases(stage, updated_at DESC);

  CREATE TABLE IF NOT EXISTS case_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    note TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS case_events_case_idx ON case_events(case_id, created_at);

  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at);
`);

const caseColumns = database.prepare("PRAGMA table_info(cases)").all();
if (!caseColumns.some((column) => column.name === "closed_by_role")) {
  database.exec("ALTER TABLE cases ADD COLUMN closed_by_role TEXT");
}

module.exports = { database };
