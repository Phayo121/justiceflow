"use strict";

const { database } = require("../db");
const { createId, hashPassword } = require("../auth");

function prompt(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    let value = "";
    const onData = (chunk) => {
      for (const key of chunk) {
        if (key === "\u0003") {
          process.stdout.write("\n");
          process.exit(130);
        }
        if (key === "\r" || key === "\n") {
          process.stdin.off("data", onData);
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (key === "\u007f" || key === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        value += key;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function main() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("Run this command in an interactive terminal so passwords are not exposed in shell history.");
  }
  process.stdin.setEncoding("utf8");
  const hasAdmin = database.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
  const username = (await prompt("Administrator username: ")).trim().toLowerCase();
  const displayName = (await prompt("Administrator display name: ")).trim();

  process.stdout.write("Administrator password (hidden): ");
  process.stdin.setRawMode(true);
  let password;
  try {
    password = await prompt("");
  } finally {
    process.stdin.setRawMode(false);
  }

  if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
    throw new Error("Username must be 3–32 characters: letters, numbers, period, underscore, or hyphen.");
  }
  if (displayName.length < 2 || displayName.length > 80) {
    throw new Error("Display name must be between 2 and 80 characters.");
  }
  if (password.length < 12 || password.length > 128) {
    throw new Error("Password must be between 12 and 128 characters.");
  }
  if (hasAdmin && process.env.ALLOW_ADDITIONAL_ADMIN !== "true") {
    throw new Error("An administrator already exists. Set ALLOW_ADDITIONAL_ADMIN=true to explicitly add another.");
  }

  const credentials = await hashPassword(password);
  database.prepare(`
    INSERT INTO users (id, username, display_name, role, password_salt, password_hash, must_change_password, created_at)
    VALUES (?, ?, ?, 'admin', ?, ?, 0, ?)
  `).run(createId(), username, displayName, credentials.salt, credentials.hash, new Date().toISOString());
  process.stdout.write(`Administrator "${username}" created. Keep these credentials private.\n`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
}).finally(() => {
  database.close();
});
