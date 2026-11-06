import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "./db.js";

const router = Router();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const BCRYPT_ROUNDS = 12;
// Used to keep login timing similar when the email does not exist.
const DUMMY_HASH = bcrypt.hashSync("dummy-password", BCRYPT_ROUNDS);
const deleteUserStmt = db.prepare("DELETE FROM users WHERE id = ?");
const getUserStmt = db.prepare("SELECT id, email FROM users WHERE id = ?");
const updateUserEmailStmt = db.prepare("UPDATE users SET email = ? WHERE id = ?");
const updateUserPasswordStmt = db.prepare("UPDATE users SET password_hash = ? WHERE id = ?");

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "1h",
  });
}

function readCredentials(body) {
  const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body?.password === "string" ? body.password : "";
  return { email, password };
}

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

router.post("/signup", async (req, res) => {
  const { email, password } = readCredentials(req.body);

  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: "Invalid email" });
  }
  if (password.length < 8 || password.length > 72) {
    // bcrypt only uses the first 72 bytes, so cap the length.
    return res.status(400).json({ error: "Password must be 8-72 characters" });
  }

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  try {
    const info = db
      .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
      .run(email, hash);
    const user = { id: info.lastInsertRowid, email };
    res.status(201).json({ user, token: signToken(user) });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = readCredentials(req.body);

  const row = db
    .prepare("SELECT id, email, password_hash FROM users WHERE email = ?")
    .get(email);

  const ok = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);
  if (!row || !ok) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const user = { id: row.id, email: row.email };
  res.json({ user, token: signToken(user) });
});

router.get("/me", requireAuth, (req, res) => {
  const row = getUserStmt.get(Number(req.user.sub));
  if (!row) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ user: { id: row.id, email: row.email } });
});

router.put("/me", requireAuth, async (req, res) => {
  const userId = Number(req.user.sub);
  const row = getUserStmt.get(userId);
  if (!row) {
    return res.status(404).json({ error: "User not found" });
  }

  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (email && !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: "Invalid email" });
  }
  if (password && (password.length < 8 || password.length > 72)) {
    return res.status(400).json({ error: "Password must be 8-72 characters" });
  }

  try {
    if (email && email !== row.email) {
      updateUserEmailStmt.run(email, userId);
    }
    if (password) {
      const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      updateUserPasswordStmt.run(hash, userId);
    }

    const updated = getUserStmt.get(userId);
    res.json({ user: { id: updated.id, email: updated.email }, token: signToken(updated) });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.delete("/me", requireAuth, (req, res) => {
  try {
    const info = deleteUserStmt.run(Number(req.user.sub));
    if (info.changes === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
