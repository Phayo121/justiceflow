"use strict";

const { promisify } = require("node:util");
const {
  createHash,
  randomBytes,
  scrypt: scryptCallback,
  timingSafeEqual,
  randomUUID
} = require("node:crypto");

const scrypt = promisify(scryptCallback);
const SCRYPT_LENGTH = 64;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, SCRYPT_LENGTH, SCRYPT_OPTIONS);
  return { salt: salt.toString("hex"), hash: Buffer.from(derived).toString("hex") };
}

async function verifyPassword(password, saltHex, hashHex) {
  const expected = Buffer.from(hashHex, "hex");
  const actual = Buffer.from(await scrypt(password, Buffer.from(saltHex, "hex"), expected.length, SCRYPT_OPTIONS));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function createToken() {
  return randomBytes(32).toString("base64url");
}

function createId() {
  return randomUUID();
}

module.exports = { createId, createToken, hashPassword, hashToken, verifyPassword };
