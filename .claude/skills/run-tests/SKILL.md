---
description: Run the node-auth test suite with yarn test and report the results. Use only when the user asks to run tests.
disable-model-invocation: true
---
1. From the project root, run `yarn install` only if `node_modules` is missing.
2. Run `yarn test` (this runs `node --test`).
3. If tests fail, report each failing test name and its assertion message. Do not edit `.env`, `app.db`, or any file under `test/` unless the user asks.
4. Report the pass, fail, and skip counts.

Sources: https://nodejs.org/api/test.html
