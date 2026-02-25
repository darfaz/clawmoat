# AGENTS.md

## Cursor Cloud specific instructions

**ClawMoat** is a Node.js CLI/library for AI agent security (prompt injection detection, secret scanning, policy enforcement). Zero runtime dependencies — pure Node.js built-ins only.

### Services

| Service | Required | How to run |
|---------|----------|------------|
| **Core CLI/Library** | Yes | `node bin/clawmoat.js <command>` |
| **SaaS Server** (`server/`) | No | `cd server && node index.js` (requires `STRIPE_SECRET_KEY`) |

### Testing

- **Node test runner (180 tests):** `node --test test/*.test.js`
  - Note: `npm test` uses `node --test test/` which fails with `MODULE_NOT_FOUND` — use the glob form above instead.
- **Built-in CLI test suite (68 tests):** `node bin/clawmoat.js test`
- Both test suites must pass before submitting changes.

### Linting

- `npm run lint` (`eslint src/`) is defined in `package.json` but **no ESLint config file exists** in the repo. Linting is not functional until an ESLint config is added.

### Key caveats

- The root `package.json` `start` script points to `src/server.js` which does not exist. The actual server is at `server/index.js`.
- The `server/` directory has its own `package.json` with a `stripe` dependency — run `npm install` there separately.
- Code style: CommonJS, no semicolons. See `CONTRIBUTING.md`.
