# Contributing to ClawMoat

Thanks for your interest in making AI agents safer! 🏰

## Running Tests

```bash
node bin/clawmoat.js test
```

All 37 tests must pass before submitting a PR.

## Adding a New Scanner Module

1. Create your scanner in `src/scanners/your-scanner.js`
2. Export a `scan(input, options)` function that returns `{ blocked, threats, score }`
3. Register it in `src/index.js`
4. Add tests in `test/` — aim for both detection and false-positive coverage
5. Update `README.md` with the new feature

Scanner template:

```javascript
function scan(input, options = {}) {
  const threats = [];
  // Detection logic here
  return {
    blocked: threats.length > 0,
    threats,
    score: threats.length > 0 ? 1.0 : 0.0,
  };
}

module.exports = { scan };
```

## PR Guidelines

- **Tests required** — every PR must include tests and all existing tests must pass
- **Zero dependencies** — ClawMoat has zero runtime dependencies. Do not add any. Use Node.js built-ins only.
- **One concern per PR** — keep PRs focused and reviewable
- **Describe what and why** — include context in your PR description

## Code Style

- CommonJS (`require`/`module.exports`)
- No semicolons (match existing style — check the codebase)
- Descriptive variable names
- Keep functions small and focused
- No external linters or formatters required — just match what's there

## Good First Issues

Looking for a place to start? Check out issues labeled [**good first issue**](https://github.com/darfaz/clawmoat/labels/good%20first%20issue).

## Questions?

Open an [issue](https://github.com/darfaz/clawmoat/issues) — we're happy to help.
