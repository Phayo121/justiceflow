"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { promisify } = require("node:util");
const { scrypt: scryptCallback } = require("node:crypto");
const { database } = require("./db");
const { createId, createToken, hashPassword, hashToken, verifyPassword } = require("./auth");

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "127.0.0.1";
const PRODUCTION = process.env.NODE_ENV === "production";
const COOKIE_NAME = "justice_session";
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;
const ROLE_PATHS = new Map([
  ["/police", "police"],
  ["/prosecution", "prosecution"],
  ["/court", "court"],
  ["/corrections", "corrections"],
  ["/admin", "admin"]
]);
const PAGES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/login", ["login.html", "text/html; charset=utf-8"]],
  ["/login.html", ["login.html", "text/html; charset=utf-8"]],
  ["/change-password", ["login.html", "text/html; charset=utf-8"]],
  ["/workspace.html", ["workspace.html", "text/html; charset=utf-8"]],
  ["/site.css", ["site.css", "text/css; charset=utf-8"]],
  ["/login.js", ["login.js", "text/javascript; charset=utf-8"]],
  ["/workspace.css", ["workspace.css", "text/css; charset=utf-8"]],
  ["/workspace.js", ["workspace.js", "text/javascript; charset=utf-8"]]
]);
const loginAttempts = new Map();
const scrypt = promisify(scryptCallback);

function now() {
  return new Date().toISOString();
}

function send(response, status, body, extraHeaders = {}) {
  const headers = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...extraHeaders
  };
  if (PRODUCTION) headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  response.writeHead(status, headers);
  response.end(body);
}

function json(response, status, value, headers = {}) {
  send(response, status, JSON.stringify(value), { "Content-Type": "application/json; charset=utf-8", ...headers });
}

function redirect(response, location, headers = {}) {
  send(response, 302, "", { Location: location, ...headers });
}

function getCookies(request) {
  const result = {};
  for (const part of (request.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) result[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
  }
  return result;
}

function sessionCookie(token, expiresAt) {
  const parts = [`${COOKIE_NAME}=${token}`, "Path=/", "HttpOnly", "SameSite=Strict", `Expires=${expiresAt.toUTCString()}`];
  if (PRODUCTION) parts.push("Secure");
  return parts.join("; ");
}

function clearSessionCookie() {
  const parts = [`${COOKIE_NAME}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (PRODUCTION) parts.push("Secure");
  return parts.join("; ");
}

function getAuthenticatedUser(request) {
  const token = getCookies(request)[COOKIE_NAME];
  if (!token || token.length > 100) return null;
  const row = database.prepare(`
    SELECT u.id, u.username, u.display_name AS displayName, u.role,
           u.must_change_password AS mustChangePassword, u.disabled,
           s.token_hash AS tokenHash
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(hashToken(token), now());
  if (!row || row.disabled) return null;
  return { ...row, mustChangePassword: Boolean(row.mustChangePassword), token };
}

function requireSameOrigin(request, response) {
  const origin = request.headers.origin;
  if (!origin || !request.headers.host) {
    json(response, 403, { error: "Request origin could not be verified." });
    return false;
  }
  try {
    const parsed = new URL(origin);
    if (parsed.host !== request.headers.host || (PRODUCTION && parsed.protocol !== "https:")) {
      json(response, 403, { error: "Cross-origin requests are not allowed." });
      return false;
    }
    return true;
  } catch {
    json(response, 403, { error: "Request origin could not be verified." });
    return false;
  }
}

function readJson(request, response) {
  return new Promise((resolve, reject) => {
    const contentType = String(request.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (contentType !== "application/json") {
      json(response, 415, { error: "Content-Type must be application/json." });
      request.resume();
      reject(new Error("response-sent"));
      return;
    }

    let size = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        json(response, 413, { error: "Request body is too large." });
        request.resume();
        reject(new Error("response-sent"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (response.writableEnded) return;
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Expected a JSON object.");
        resolve(parsed);
      } catch {
        json(response, 400, { error: "Request body must be a valid JSON object." });
        reject(new Error("response-sent"));
      }
    });
    request.on("error", reject);
  });
}

function audit(actorId, action, entityType, entityId = null) {
  database.prepare("INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(createId(), actorId, action, entityType, entityId, now());
}

function roleWorkspace(role) {
  return role === "admin" ? "/admin" : `/${role}`;
}

function canAccessCase(role, stage, closedByRole) {
  if (stage === "Closed") return role === closedByRole;
  const visible = {
    police: ["Police intake"],
    prosecution: ["Prosecutor review"],
    court: ["Court proceedings"],
    corrections: ["Correctional custody"]
  };
  return Boolean(visible[role]?.includes(stage));
}

function getCase(caseId, role) {
  const item = database.prepare(`
    SELECT id, alias, offence_category AS offenceCategory, station, stage, closed_by_role AS closedByRole,
           created_at AS createdAt, updated_at AS updatedAt
    FROM cases WHERE id = ?
  `).get(caseId);
  if (!item || !canAccessCase(role, item.stage, item.closedByRole)) return null;
  item.events = database.prepare(`
    SELECT e.stage, e.note, e.created_at AS createdAt, u.display_name AS actor
    FROM case_events e JOIN users u ON u.id = e.actor_id
    WHERE e.case_id = ? ORDER BY e.created_at, e.id
  `).all(caseId);
  return item;
}

function validateText(value, label, maximum, minimum = 1) {
  if (typeof value !== "string") return `${label} is required.`;
  const clean = value.trim();
  if (clean.length < minimum || clean.length > maximum) return `${label} must be ${minimum}–${maximum} characters.`;
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(clean)) return `${label} contains unsupported control characters.`;
  return null;
}

function loginWindow(ip) {
  const cutoff = Date.now() - 15 * 60 * 1000;
  const timestamps = (loginAttempts.get(ip) || []).filter((timestamp) => timestamp > cutoff);
  loginAttempts.set(ip, timestamps);
  return timestamps;
}

async function handleLogin(request, response) {
  if (!requireSameOrigin(request, response)) return;
  const attempts = loginWindow(request.socket.remoteAddress || "unknown");
  if (attempts.length >= 10) {
    json(response, 429, { error: "Too many sign-in attempts. Try again later." }, { "Retry-After": "900" });
    return;
  }
  const body = await readJson(request, response);
  const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (username.length > 32 || password.length > 128) {
    attempts.push(Date.now());
    json(response, 401, { error: "Invalid username or password." });
    return;
  }

  const user = database.prepare(`
    SELECT id, username, display_name AS displayName, role, password_salt AS salt,
           password_hash AS passwordHash, must_change_password AS mustChangePassword, disabled
    FROM users WHERE username = ? COLLATE NOCASE
  `).get(username);
  const salt = user?.salt || "00000000000000000000000000000000";
  const passwordHash = user?.passwordHash || "0".repeat(128);
  const valid = await verifyPassword(password, salt, passwordHash);
  if (!user || !valid || user.disabled) {
    attempts.push(Date.now());
    json(response, 401, { error: "Invalid username or password." });
    return;
  }

  loginAttempts.delete(request.socket.remoteAddress || "unknown");
  const token = createToken();
  const expiresAt = new Date(Date.now() + SESSION_MS);
  database.prepare("INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .run(hashToken(token), user.id, expiresAt.toISOString(), now());
  audit(user.id, "sign_in", "session");
  json(response, 200, {
    workspace: user.mustChangePassword ? "/change-password" : roleWorkspace(user.role),
    mustChangePassword: Boolean(user.mustChangePassword)
  }, { "Set-Cookie": sessionCookie(token, expiresAt) });
}

function visibleStageList(role) {
  return {
    police: ["Police intake"],
    prosecution: ["Prosecutor review"],
    court: ["Court proceedings"],
    corrections: ["Correctional custody"]
  }[role] || [];
}

async function handleApi(request, response, url) {
  const pathname = url.pathname;
  const method = request.method;

  if (pathname === "/api/login" && method === "POST") {
    await handleLogin(request, response);
    return;
  }

  if (pathname === "/api/session" && method === "GET") {
    const user = getAuthenticatedUser(request);
    if (!user) {
      json(response, 401, { error: "Sign in is required." });
      return;
    }
    if (user.mustChangePassword) {
      json(response, 428, { error: "Change your temporary password to continue." });
      return;
    }
    json(response, 200, { user: { username: user.username, displayName: user.displayName, role: user.role } });
    return;
  }

  if (method !== "GET" && !requireSameOrigin(request, response)) return;

  if (pathname === "/api/logout" && method === "POST") {
    const user = getAuthenticatedUser(request);
    if (user) {
      database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(user.tokenHash);
      audit(user.id, "sign_out", "session");
    }
    json(response, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
    return;
  }

  const user = getAuthenticatedUser(request);
  if (!user) {
    json(response, 401, { error: "Sign in is required." });
    return;
  }
  if (user.mustChangePassword && pathname !== "/api/password") {
    json(response, 428, { error: "Change your temporary password to continue." });
    return;
  }

  if (pathname === "/api/password" && method === "POST") {
    const body = await readJson(request, response);
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length < 12 || password.length > 128) {
      json(response, 400, { error: "Password must be between 12 and 128 characters." });
      return;
    }
    const credentials = await hashPassword(password);
    database.prepare("UPDATE users SET password_salt = ?, password_hash = ?, must_change_password = 0 WHERE id = ?")
      .run(credentials.salt, credentials.hash, user.id);
    database.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?").run(user.id, user.tokenHash);
    audit(user.id, "password_changed", "user", user.id);
    json(response, 200, { workspace: roleWorkspace(user.role) });
    return;
  }

  if (pathname === "/api/cases" && method === "GET") {
    if (user.role === "admin") {
      json(response, 403, { error: "Administrator accounts do not have case-record access." });
      return;
    }
    const allowed = visibleStageList(user.role);
    const placeholders = allowed.map(() => "?").join(", ");
    const rows = allowed.length ? database.prepare(`
      SELECT id, alias, offence_category AS offenceCategory, station, stage,
             created_at AS createdAt, updated_at AS updatedAt
      FROM cases
      WHERE stage IN (${placeholders}) OR (stage = 'Closed' AND closed_by_role = ?)
      ORDER BY updated_at DESC LIMIT 200
    `).all(...allowed, user.role) : database.prepare(`
      SELECT id, alias, offence_category AS offenceCategory, station, stage,
             created_at AS createdAt, updated_at AS updatedAt
      FROM cases WHERE stage = 'Closed' AND closed_by_role = ?
      ORDER BY updated_at DESC LIMIT 200
    `).all(user.role);
    json(response, 200, { cases: rows });
    return;
  }

  if (pathname === "/api/cases" && method === "POST") {
    if (user.role !== "police") {
      json(response, 403, { error: "Only police-role accounts can register an intake record." });
      return;
    }
    const body = await readJson(request, response);
    const values = [
      ["alias", body.alias, 80, 2],
      ["Offence category", body.offenceCategory, 100],
      ["Police station", body.station, 100],
      ["Intake note", body.note, 1000, 2]
    ];
    for (const [label, value, max, min] of values) {
      const error = validateText(value, label, max, min);
      if (error) {
        json(response, 400, { error });
        return;
      }
    }
    const caseId = `ES-${new Date().getUTCFullYear()}-${createId().slice(0, 8).toUpperCase()}`;
    const createdAt = now();
    database.exec("BEGIN IMMEDIATE");
    try {
      database.prepare(`
        INSERT INTO cases (id, alias, offence_category, station, stage, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'Police intake', ?, ?, ?)
      `).run(caseId, body.alias.trim(), body.offenceCategory.trim(), body.station.trim(), user.id, createdAt, createdAt);
      database.prepare("INSERT INTO case_events (id, case_id, stage, note, actor_id, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(createId(), caseId, "Police intake", body.note.trim(), user.id, createdAt);
      audit(user.id, "case_created", "case", caseId);
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    json(response, 201, { case: { id: caseId } });
    return;
  }

  const detailMatch = pathname.match(/^\/api\/cases\/([^/]+)$/);
  if (detailMatch && method === "GET") {
    let caseId;
    try { caseId = decodeURIComponent(detailMatch[1]); } catch {
      json(response, 400, { error: "Invalid case reference." });
      return;
    }
    const record = getCase(caseId, user.role);
    if (!record) {
      json(response, 404, { error: "Case not found or not available to your role." });
      return;
    }
    audit(user.id, "case_viewed", "case", caseId);
    json(response, 200, { case: record });
    return;
  }

  const handoffMatch = pathname.match(/^\/api\/cases\/([^/]+)\/handoff$/);
  if (handoffMatch && method === "POST") {
    let caseId;
    try { caseId = decodeURIComponent(handoffMatch[1]); } catch {
      json(response, 400, { error: "Invalid case reference." });
      return;
    }
    const body = await readJson(request, response);
    const transitions = {
      police: { from: "Police intake", to: ["Prosecutor review"] },
      prosecution: { from: "Prosecutor review", to: ["Court proceedings", "Closed"] },
      court: { from: "Court proceedings", to: ["Correctional custody", "Closed"] },
      corrections: { from: "Correctional custody", to: ["Closed"] }
    };
    const transition = transitions[user.role];
    const current = database.prepare("SELECT stage, closed_by_role AS closedByRole FROM cases WHERE id = ?").get(caseId);
    if (!current || !transition || !canAccessCase(user.role, current.stage, current.closedByRole)) {
      json(response, 404, { error: "Case not found or not available to your role." });
      return;
    }
    if (current.stage !== transition.from || !transition.to.includes(body.stage)) {
      json(response, 409, { error: "This case cannot be handed off to that stage by your role." });
      return;
    }
    const error = validateText(body.note, "Handoff note", 1000, 2);
    if (error) {
      json(response, 400, { error });
      return;
    }
    const updatedAt = now();
    database.exec("BEGIN IMMEDIATE");
    try {
      const update = database.prepare("UPDATE cases SET stage = ?, closed_by_role = ?, updated_at = ? WHERE id = ? AND stage = ?")
        .run(body.stage, body.stage === "Closed" ? user.role : null, updatedAt, caseId, transition.from);
      if (Number(update.changes) !== 1) {
        database.exec("ROLLBACK");
        json(response, 409, { error: "The case changed before this handoff. Reload and try again." });
        return;
      }
      database.prepare("INSERT INTO case_events (id, case_id, stage, note, actor_id, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(createId(), caseId, body.stage, body.note.trim(), user.id, updatedAt);
      audit(user.id, "case_handoff", "case", caseId);
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    const updatedCase = getCase(caseId, user.role);
    json(response, 200, { case: updatedCase || { id: caseId, stage: body.stage } });
    return;
  }

  if (pathname === "/api/admin/users" && method === "POST") {
    if (user.role !== "admin") {
      json(response, 403, { error: "Administrator access is required." });
      return;
    }
    const body = await readJson(request, response);
    const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
    const usernameError = validateText(username, "Username", 32, 3);
    if (usernameError || !/^[a-z0-9._-]+$/.test(username)) {
      json(response, 400, { error: "Username must be 3–32 characters using letters, numbers, period, underscore, or hyphen." });
      return;
    }
    const nameError = validateText(body.displayName, "Display name", 80, 2);
    if (nameError) {
      json(response, 400, { error: nameError });
      return;
    }
    const roles = ["police", "prosecution", "court", "corrections"];
    if (!roles.includes(body.role)) {
      json(response, 400, { error: "Choose an authorized agency role." });
      return;
    }
    if (typeof body.password !== "string" || body.password.length < 12 || body.password.length > 128) {
      json(response, 400, { error: "Temporary password must be between 12 and 128 characters." });
      return;
    }
    if (database.prepare("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE").get(username)) {
      json(response, 409, { error: "That username is already in use." });
      return;
    }
    const credentials = await hashPassword(body.password);
    const userId = createId();
    database.prepare(`
      INSERT INTO users (id, username, display_name, role, password_salt, password_hash, must_change_password, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `).run(userId, username, body.displayName.trim(), body.role, credentials.salt, credentials.hash, now());
    audit(user.id, "user_created", "user", userId);
    json(response, 201, { user: { username, role: body.role } });
    return;
  }

  json(response, 404, { error: "API endpoint not found." });
}

function serveFile(response, route, isHead) {
  const [filename, contentType] = PAGES.get(route);
  fs.readFile(path.join(__dirname, "site", filename), (error, contents) => {
    if (error) {
      console.error(`Unable to read public page ${filename}:`, error);
      send(response, 500, "Unable to load the requested page.", { "Content-Type": "text/plain; charset=utf-8" });
      return;
    }
    send(response, 200, isHead ? "" : contents, { "Content-Type": contentType });
  });
}

const server = http.createServer(async (request, response) => {
  let url;
  try {
    url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  } catch {
    json(response, 400, { error: "Invalid request URL." });
    return;
  }

  try {
    if (url.pathname.startsWith("/api/")) {
      if (request.method !== "GET" && request.method !== "POST") {
        json(response, 405, { error: "Method not allowed." }, { Allow: "GET, POST" });
        return;
      }
      await handleApi(request, response, url);
      return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      send(response, 405, "Method not allowed.", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      return;
    }

    const user = getAuthenticatedUser(request);
    if (ROLE_PATHS.has(url.pathname)) {
      if (!user) {
        redirect(response, "/login");
        return;
      }
      if (user.mustChangePassword) {
        redirect(response, "/change-password");
        return;
      }
      if (user.role !== ROLE_PATHS.get(url.pathname)) {
        redirect(response, roleWorkspace(user.role));
        return;
      }
      serveFile(response, "/workspace.html", request.method === "HEAD");
      return;
    }

    if (url.pathname === "/workspace" || url.pathname === "/workspace.html") {
      if (!user) {
        redirect(response, "/login");
        return;
      }
      if (user.mustChangePassword) {
        redirect(response, "/change-password");
        return;
      }
      redirect(response, roleWorkspace(user.role));
      return;
    }

    if (url.pathname === "/change-password") {
      if (!user) {
        redirect(response, "/login");
        return;
      }
      if (!user.mustChangePassword) {
        redirect(response, roleWorkspace(user.role));
        return;
      }
      serveFile(response, "/login", request.method === "HEAD");
      return;
    }

    if (url.pathname === "/login" || url.pathname === "/login.html") {
      if (user) {
        redirect(response, user.mustChangePassword ? "/change-password" : roleWorkspace(user.role));
        return;
      }
      serveFile(response, "/login", request.method === "HEAD");
      return;
    }

    if (url.pathname === "/") {
      if (request.method === "HEAD") {
        serveFile(response, "/", true);
        return;
      }
      serveFile(response, "/", false);
      return;
    }

    if (PAGES.has(url.pathname)) {
      serveFile(response, url.pathname, request.method === "HEAD");
      return;
    }

    send(response, 404, "Not found.", { "Content-Type": "text/plain; charset=utf-8" });
  } catch (error) {
    if (error.message === "response-sent" || response.writableEnded) return;
    console.error("Request failed:", error);
    if (url.pathname.startsWith("/api/")) json(response, 500, { error: "The request could not be completed." });
    else send(response, 500, "The request could not be completed.", { "Content-Type": "text/plain; charset=utf-8" });
  }
});

server.on("error", (error) => {
  console.error("Unable to start the JusticeFlow server:", error.message);
  process.exitCode = 1;
});

server.listen(PORT, HOST, () => {
  console.log(`JusticeFlow is listening on http://${HOST}:${PORT}`);
  if (!PRODUCTION) console.warn("Development mode: bind to loopback only; do not enter real case data.");
});

function shutdown() {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
