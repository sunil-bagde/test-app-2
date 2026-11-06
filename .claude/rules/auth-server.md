---
paths:
  - "server.js"
  - "auth.js"
  - "db.js"
---
# Express API, auth and SQLite

- Keep the existing Express 4 style: `Router`, `express.json({ limit })`, and the middleware order in `server.js`.
- Express does not catch errors from async handlers on its own in this setup. Wrap `await` calls in `try/catch` and call `next(err)`, or return a 500 JSON error as `/signup` does. Never let a rejected promise go unhandled.
- Use `db.prepare(...)` with `?` placeholders for every query. Never build SQL with string concatenation. Use `db.exec` only for fixed schema SQL.
- Map SQLite errors by `err.code`, for example `SQLITE_CONSTRAINT_UNIQUE` to 409.
- Keep `helmet()` and the `express.json` size limit in place. Do not remove security middleware to make a test pass.
- The JWT secret comes only from `process.env.JWT_SECRET`, set in the server environment or `.env`. Never hard-code it, log it, return it in responses, or commit real values. `.env` is local config and must stay out of git.
- Sign tokens with `algorithm: "HS256"` and verify with `algorithms: ["HS256"]`, as `auth.js` already does. Keep the token lifetime set by `expiresIn`.
- Hash passwords only with bcrypt through `bcryptjs`. Keep the password length cap of 72 bytes. The bcrypt docs say only the first 72 bytes are used.
- Keep the dummy-hash compare in login so the response time does not reveal whether an email exists.
- Do not add a dependency without asking the user.

Sources: https://expressjs.com/en/guide/error-handling.html, https://raw.githubusercontent.com/WiseLibs/better-sqlite3/master/docs/api.md, https://raw.githubusercontent.com/auth0/node-jsonwebtoken/master/README.md, https://raw.githubusercontent.com/kelektiv/node.bcrypt.js/master/README.md, https://helmetjs.github.io/
