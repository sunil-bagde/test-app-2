---
paths:
  - "test/**/*.js"
---
# Node test runner tests

- Use `node:test` with `describe`/`it` or `test` and `node:assert`. Do not add a test framework without asking.
- Run the suite with `yarn test`, which runs `node --test`.
- `server.js` exits the process when `JWT_SECRET` is missing or shorter than 32 characters. It checks at import time. ESM imports are hoisted, so set `process.env.JWT_SECRET` and `process.env.DB_PATH` first, then load the app with a dynamic `await import("../server.js")`.
- `db.js` opens the database when it is imported. Point `DB_PATH` at a temporary file and delete it in an `after()` hook. Never use the real `app.db` or `.env` values.
- `server.js` exports `app` and only calls `listen` when run directly. Tests should start the app on an ephemeral port, such as `server.listen(0)`, make real HTTP requests, and close the server when done. Do not start a separate server process.
- Put one behavior per `it`. Assert the status code and the JSON body for each response.
- Never hard-code real secrets in tests. Use a random or obviously fake `JWT_SECRET` that is at least 32 characters long.

Sources: https://nodejs.org/api/test.html
