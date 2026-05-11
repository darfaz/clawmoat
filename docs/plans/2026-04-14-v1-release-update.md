# ClawMoat v1.0.0 update

## What changed

ClawMoat is moving from a fast-moving v0 project to a stable v1 product category:

**The open-source agent firewall.**

This is not just a semantic version bump.
It is a category claim.

The product now has enough surface area and enough market validation to stop sounding like an experiment:

- prompt injection scanning
- outbound secret and exfiltration scanning
- policy engine
- enforcement middleware
- MCP scanner
- supply chain scanner
- host/runtime controls
- live monitoring dashboard
- audit trail
- framework integrations

That is a real security product.

## Why now

The market just got a cleaner narrative.

WSJ framed the next phase as **bugmageddon**: AI getting much better at vulnerability discovery.

That matters because:
- bug discovery accelerates
- exploit discovery becomes cheaper
- patching remains slow
- agents already have high privileges

So ClawMoat’s job is clearer than ever:

**contain what agents can do when vulnerabilities are inevitable**

## New top-line message

**They protect the model. ClawMoat protects the machine.**

Backup line:

**As AI finds bugs faster, runtime containment stops being optional.**

## What shipped in this update

1. Homepage hero updated to v1.0.0 framing
2. New blog post: `blog/bugmageddon-agent-firewall.html`
3. Blog index updated with the new post and v1 tag
4. Package version moved to `1.0.0`
5. Version references updated in formatter tests/docs where needed
6. Marketing pack created for X, Reddit, HN, LinkedIn, Dev.to, homepage copy

## What still needs to happen

### Release hygiene
- run tests
- publish npm package as `1.0.0`
- tag GitHub release
- add release notes to README or GitHub Releases

### Distribution
- post X thread manually if API credits still dead
- post Reddit piece manually
- publish Dev.to version
- announce in GitHub README / release notes

### Strong next product moves
- `clawmoat doctor` or `clawmoat exposure` command that outputs a shareable risk summary
- first-class MCP risk scoring report
- clearer “monitor vs enforce” onboarding path
- more obvious enterprise / team runtime policy story

## Julian take

Going to v1 is right.

The mistake would be calling it v1 while still talking like a hobby scanner.

So the real upgrade is not the version number.
It is the language:

- from “security tool” to **agent firewall**
- from “prompt injection detection” to **runtime containment**
- from “nice to have” to **mandatory infrastructure for over-permissioned agents**
