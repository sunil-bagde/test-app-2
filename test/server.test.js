import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

process.env.JWT_SECRET = "test-secret-that-is-at-least-32-characters";
const tempDir = await mkdtemp(join(tmpdir(), "node-auth-test-"));
process.env.DB_PATH = join(tempDir, "test.db");

const { app } = await import("../server.js");
let server;
let baseUrl;
const credentials = { email: "  TEST@example.com ", password: "correct-horse" };

async function postJson(path, body) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

before(async () => {
  server = app.listen(0);
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  await rm(tempDir, { recursive: true, force: true });
});

test("GET /health returns a successful health response", async () => {
  const response = await fetch(`${baseUrl}/health`);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});

test("responses include Helmet security headers", async () => {
  const response = await fetch(`${baseUrl}/health`);

  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "SAMEORIGIN");
});

test("JSON request bodies larger than 10kb are rejected", async () => {
  const response = await postJson("/auth/login", {
    email: "a@example.com",
    password: "x".repeat(11_000),
  });

  assert.equal(response.status, 413);
});

test("signup validates email and password", async () => {
  const invalidEmail = await postJson("/auth/signup", {
    email: "not-an-email",
    password: "long-enough",
  });
  assert.equal(invalidEmail.status, 400);
  assert.deepEqual(await invalidEmail.json(), { error: "Invalid email" });

  for (const password of ["short", "x".repeat(73)]) {
    const invalidPassword = await postJson("/auth/signup", {
      email: "validation@example.com",
      password,
    });
    assert.equal(invalidPassword.status, 400);
    assert.deepEqual(await invalidPassword.json(), {
      error: "Password must be 8-72 characters",
    });
  }
});

test("signup normalizes email, returns a token, and rejects duplicate accounts", async () => {
  const response = await postJson("/auth/signup", credentials);
  const result = await response.json();

  assert.equal(response.status, 201);
  assert.deepEqual(result.user, { id: 1, email: "test@example.com" });
  assert.equal(typeof result.token, "string");

  const duplicate = await postJson("/auth/signup", {
    email: "test@example.com",
    password: credentials.password,
  });
  assert.equal(duplicate.status, 409);
  assert.deepEqual(await duplicate.json(), { error: "Email already registered" });
});

test("login accepts valid credentials and rejects invalid credentials", async () => {
  const response = await postJson("/auth/login", {
    email: "TEST@example.com",
    password: credentials.password,
  });
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.user, { id: 1, email: "test@example.com" });
  assert.equal(typeof result.token, "string");

  for (const invalidCredentials of [
    { email: "test@example.com", password: "wrong-password" },
    { email: "unknown@example.com", password: credentials.password },
  ]) {
    const invalid = await postJson("/auth/login", invalidCredentials);
    assert.equal(invalid.status, 401);
    assert.deepEqual(await invalid.json(), { error: "Invalid email or password" });
  }
});

test("GET /auth/me requires a valid token and returns the authenticated user", async () => {
  const missingToken = await fetch(`${baseUrl}/auth/me`);
  assert.equal(missingToken.status, 401);
  assert.deepEqual(await missingToken.json(), { error: "Missing token" });

  const invalidToken = await fetch(`${baseUrl}/auth/me`, {
    headers: { authorization: "Bearer invalid-token" },
  });
  assert.equal(invalidToken.status, 401);
  assert.deepEqual(await invalidToken.json(), { error: "Invalid or expired token" });

  const login = await postJson("/auth/login", {
    email: "test@example.com",
    password: credentials.password,
  });
  const { token } = await login.json();
  const authenticated = await fetch(`${baseUrl}/auth/me`, {
    headers: { authorization: `Bearer ${token}` },
  });

  assert.equal(authenticated.status, 200);
  assert.deepEqual(await authenticated.json(), {
    user: { id: 1, email: "test@example.com" },
  });
});

async function putJson(path, body, token) {
  return fetch(`${baseUrl}${path}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
}

test("PUT /auth/me requires authentication", async () => {
  const noToken = await fetch(`${baseUrl}/auth/me`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "new@example.com" }),
  });
  assert.equal(noToken.status, 401);
  assert.deepEqual(await noToken.json(), { error: "Missing token" });

  const badToken = await fetch(`${baseUrl}/auth/me`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer invalid-token",
    },
    body: JSON.stringify({ email: "new@example.com" }),
  });
  assert.equal(badToken.status, 401);
  assert.deepEqual(await badToken.json(), { error: "Invalid or expired token" });
});

test("PUT /auth/me updates email correctly", async () => {
  const login = await postJson("/auth/login", {
    email: "test@example.com",
    password: credentials.password,
  });
  const { token } = await login.json();

  const response = await putJson("/auth/me", { email: "updated@example.com" }, token);
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.user, { id: 1, email: "updated@example.com" });
  assert.equal(typeof result.token, "string");

  const login2 = await postJson("/auth/login", {
    email: "updated@example.com",
    password: credentials.password,
  });
  assert.equal(login2.status, 200);
});

test("PUT /auth/me updates password correctly", async () => {
  const login = await postJson("/auth/login", {
    email: "updated@example.com",
    password: credentials.password,
  });
  const { token } = await login.json();

  const response = await putJson("/auth/me", { password: "new-password-123" }, token);
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.equal(result.user.email, "updated@example.com");
  assert.equal(typeof result.token, "string");

  const login2 = await postJson("/auth/login", {
    email: "updated@example.com",
    password: "new-password-123",
  });
  assert.equal(login2.status, 200);
});

test("PUT /auth/me updates both email and password", async () => {
  const login = await postJson("/auth/login", {
    email: "updated@example.com",
    password: "new-password-123",
  });
  const { token } = await login.json();

  const response = await putJson(
    "/auth/me",
    { email: "both-updated@example.com", password: "another-password-456" },
    token
  );
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.user, { id: 1, email: "both-updated@example.com" });

  const login2 = await postJson("/auth/login", {
    email: "both-updated@example.com",
    password: "another-password-456",
  });
  assert.equal(login2.status, 200);
});

test("PUT /auth/me validates email format", async () => {
  const login = await postJson("/auth/login", {
    email: "both-updated@example.com",
    password: "another-password-456",
  });
  const { token } = await login.json();

  const response = await putJson("/auth/me", { email: "not-an-email" }, token);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Invalid email" });
});

test("PUT /auth/me validates password length", async () => {
  const login = await postJson("/auth/login", {
    email: "both-updated@example.com",
    password: "another-password-456",
  });
  const { token } = await login.json();

  const short = await putJson("/auth/me", { password: "short" }, token);
  assert.equal(short.status, 400);
  assert.deepEqual(await short.json(), { error: "Password must be 8-72 characters" });

  const long = await putJson("/auth/me", { password: "x".repeat(73) }, token);
  assert.equal(long.status, 400);
  assert.deepEqual(await long.json(), { error: "Password must be 8-72 characters" });
});

test("PUT /auth/me rejects duplicate email", async () => {
  const signup2 = await postJson("/auth/signup", {
    email: "other@example.com",
    password: "some-password-123",
  });
  assert.equal(signup2.status, 201);

  const login = await postJson("/auth/login", {
    email: "other@example.com",
    password: "some-password-123",
  });
  const { token } = await login.json();

  const response = await putJson("/auth/me", { email: "both-updated@example.com" }, token);
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: "Email already registered" });
});

test("PUT /auth/me returns 404 for deleted user", async () => {
  const signup3 = await postJson("/auth/signup", {
    email: "to-delete@example.com",
    password: "delete-me-password",
  });
  const { token } = await signup3.json();

  const deleteResp = await fetch(`${baseUrl}/auth/me`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(deleteResp.status, 204);

  const response = await putJson("/auth/me", { email: "survived@example.com" }, token);
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "User not found" });
});

test("PUT /auth/me with empty body returns current user", async () => {
  const login = await postJson("/auth/login", {
    email: "both-updated@example.com",
    password: "another-password-456",
  });
  const { token } = await login.json();

  const response = await putJson("/auth/me", {}, token);
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.user, { id: 1, email: "both-updated@example.com" });
  assert.equal(typeof result.token, "string");
});
