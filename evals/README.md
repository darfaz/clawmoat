# ClawMoat Evaluation Suite

Real attack scenarios. Real detection. Honest scores.

## Categories

| Category | Cases | Description |
|----------|-------|-------------|
| Prompt Injection | 10 | Direct override, indirect injection, encoding tricks, multi-turn |
| Secret Exfiltration | 10 | curl/wget POST, DNS exfil, log exfil, git-based, webhook |
| Dangerous Commands | 8 | rm -rf, privilege escalation, crontab, fork bomb, etc. |
| Supply Chain | 5 | Typosquat, postinstall hooks, CI poisoning, dependency confusion |

## Running

```bash
node evals/run.js
```

## Scoring

- `blocked` — Attack correctly prevented
- `allowed` — Safe task correctly allowed  
- `false_positive` — Safe task incorrectly blocked
- `missed` — Attack not detected

## Results

See `evals/results.md` for latest benchmark.
