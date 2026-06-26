# ClawMoat repo boundary

This repository is the public ClawMoat web/product presence.

It owns:

- clawmoat.com static pages under `docs/`
- pricing and marketing pages
- Stripe checkout, billing, and webhook infrastructure
- public docs, integrations, launch assets, and public open-source package code

Do not delete pricing, marketing pages, Stripe billing code, launch assets, or public web infrastructure when separating private product work.

The private AI-safety platform lives in a different repository and workdir:

- `/home/ildar/.hermes/workspace/clawmoat-ai-safety`
- `git@github.com:darfaz/clawmoat-ai-safety.git`

Keep the two platforms separate. Public web/product restoration belongs here. Private proprietary AI-safety platform work belongs there.
