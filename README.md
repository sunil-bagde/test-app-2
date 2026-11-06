# node-auth

A small Express authentication API with signup, login, and a protected `/auth/me` route. Users are stored in SQLite (via `better-sqlite3`). Passwords are hashed with bcrypt and sessions are stateless JWTs.

## Requirements

- Node.js 18 or newer (the test suite uses `node --test` and global `fetch`)
- Yarn (the repo includes `yarn.lock`)

## Setup

1. Install dependencies:

   ```sh
   yarn install
   ```

2. Create a `.env` file in the project root:

   ```sh
   JWT_SECRET=replace-with-a-random-string-of-at-least-32-characters
   # Optional
   PORT=3000
   DB_PATH=app.db
   ```

   | Variable     | Required | Default   | Description                                                                 |
   |--------------|----------|-----------|-----------------------------------------------------------------------------|
   | `JWT_SECRET` | yes      | —         | Secret used to sign and verify tokens. The server exits on startup if it is missing or shorter than 32 characters. |
   | `PORT`       | no       | `3000`    | Port the HTTP server listens on.                                           |
   | `DB_PATH`    | no       | `app.db`  | Path to the SQLite database file. It is created and the `users` table is added on first start. |

3. Start the server:

   ```sh
   node --env-file=.env server.js
   ```

   The server prints `Listening on http://localhost:3000` when it is ready.

   Or run `yarn start` (or `yarn dev` to restart on file changes).

## API

Base URL: `http://localhost:3000` (or whatever `PORT` is set to).

All request and response bodies are JSON. Request bodies are limited to 10 kB. Requests to `/auth/*` are rate-limited to 50 requests per 15 minutes per client IP. Responses include Helmet security headers.

### Health

#### `GET /health`

No authentication.

Response `200`:

```json
{ "ok": true }
```

### Auth

#### `POST /auth/signup`

Creates a user and returns a token.

Request body:

```json
{ "email": "user@example.com", "password": "correct-horse" }
```

- `email` must match a basic `name@domain.tld` pattern. It is trimmed and lowercased before it is stored.
- `password` must be 8–72 characters. The upper limit comes from bcrypt, which only uses the first 72 bytes.

Responses:

| Status | Body | When |
|--------|------|------|
| `201` | `{ "user": { "id": 1, "email": "user@example.com" }, "token": "<jwt>" }` | User created |
| `400` | `{ "error": "Invalid email" }` | Email fails validation |
| `400` | `{ "error": "Password must be 8-72 characters" }` | Password length out of range |
| `409` | `{ "error": "Email already registered" }` | Email is already in use |
| `500` | `{ "error": "Server error" }` | Unexpected database error |

#### `POST /auth/login`

Checks credentials and returns a token.

Request body:

```json
{ "email": "user@example.com", "password": "correct-horse" }
```

The email is trimmed and lowercased before lookup.

Responses:

| Status | Body | When |
|--------|------|------|
| `200` | `{ "user": { "id": 1, "email": "user@example.com" }, "token": "<jwt>" }` | Valid credentials |
| `401` | `{ "error": "Invalid email or password" }` | Unknown email or wrong password |

Unknown emails and wrong passwords return the same error, and both take a bcrypt comparison, so response timing does not reveal which emails exist.

#### `GET /auth/me`

Returns the signed-in user. Requires authentication.

Headers:

```
Authorization: Bearer <jwt>
```

Responses:

| Status | Body | When |
|--------|------|------|
| `200` | `{ "user": { "id": 1, "email": "user@example.com" } }` | Valid token and user exists |
| `401` | `{ "error": "Missing token" }` | No `Bearer` token in the `Authorization` header |
| `401` | `{ "error": "Invalid or expired token" }` | Token is malformed, has a bad signature, or has expired |
| `404` | `{ "error": "User not found" }` | Token is valid but the user has been deleted |

#### `DELETE /auth/me`

Deletes the signed-in user. Requires authentication.

Headers:

```
Authorization: Bearer <jwt>
```

Responses:

| Status | Body | When |
|--------|------|------|
| `204` | (empty) | User deleted |
| `401` | `{ "error": "Missing token" }` | No `Bearer` token |
| `401` | `{ "error": "Invalid or expired token" }` | Token is invalid or expired |
| `404` | `{ "error": "User not found" }` | User no longer exists |
| `500` | `{ "error": "Server error" }` | Unexpected database error |

### Tokens

- Tokens are JWTs signed with HS256 using `JWT_SECRET`.
- The payload contains `sub` (user id) and `email`.
- Tokens expire after 1 hour. Log in again to get a new one.

Example:

```sh
curl -s -X POST http://localhost:3000/auth/login \
  -H "content-type: application/json" \
  -d '{"email":"user@example.com","password":"correct-horse"}'

curl -s http://localhost:3000/auth/me \
  -H "authorization: Bearer <token from login>"
```

## Tests

The tests use Node's built-in test runner and call the real Express app over HTTP. They do not need a running server.

```sh
yarn test
```

The test file is `test/server.test.js`. It sets its own `JWT_SECRET` and a temporary `DB_PATH`, so it does not touch your real database. The temporary database is removed when the tests finish.

The suite covers:

- `GET /health` returns `{ "ok": true }`.
- Helmet security headers are present on responses.
- JSON bodies over 10 kB are rejected with `413`.
- Signup validates email and password length (8–72 characters).
- Signup normalizes email, returns a token, and rejects duplicate emails with `409`.
- Login accepts valid credentials and rejects invalid ones with `401`.
- `GET /auth/me` requires a valid bearer token.

## Project layout

| File         | Purpose                                              |
|--------------|------------------------------------------------------|
| `server.js`  | Express app setup, middleware, and `/health`         |
| `auth.js`    | `/auth` routes, JWT signing, and `requireAuth` middleware |
| `db.js`      | SQLite connection and `users` table creation         |
| `test/`      | Test suite                                           |
