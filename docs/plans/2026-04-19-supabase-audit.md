# ClawMoat Supabase audit

Date: 2026-04-19
Project: `bfnoxngfskhzgnqkwuhb`

## Executive summary

ClawMoat does use Supabase, but only in a narrow way right now.

### Confirmed usage in repo

Only one live code path in the ClawMoat repo references this Supabase project:

- `docs/affiliates/index.html`
  - browser POST to `/rest/v1/affiliates`
  - purpose: store affiliate signups

## What is NOT currently wired to Supabase in the repo

I did not find repo references showing Supabase is currently required for:

- core npm package
- CLI scans
- GitHub repo flows
- main homepage
- enforcement middleware
- MCP scanner
- prompt injection scanning
- blog/site rendering outside affiliate signup

## Blast radius if Supabase pauses

### Likely affected
- affiliate signup form submission
- any future dashboard/admin features built on the same project

### Likely unaffected
- `clawmoat` npm package itself
- GitHub repo
- core docs/site pages
- scanner runtime behavior
- local CLI usage

## Cleanup performed

Deleted the temporary keepalive test row that had been inserted into `affiliates`.

## Preventive action added

Added a read-only keepalive job:

- script: `/home/ildar/.openclaw/scripts/clawmoat-supabase-keepalive.py`
- schedule: every 3 days via crontab
- checks:
  - `auth/v1/health`
  - `rest/v1/affiliates?select=id&limit=1`

Log file:
- `/home/ildar/.openclaw/logs/clawmoat-supabase-keepalive.log`

## Recommendation

Good enough for now.

If ClawMoat starts depending more heavily on Supabase, next step should be to:
- move from inline browser fetches to a small controlled backend
- remove public coupling from the static affiliates page
- define exactly which features are allowed to depend on Supabase
