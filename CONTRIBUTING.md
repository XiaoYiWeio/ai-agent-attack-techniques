# Contributing to Awesome AI Agent Attacks

Thank you for helping document the AI agent attack surface.

## What belongs here

- Real-world attacks and incidents with references
- Reproducible techniques (PoC-level detail is fine; working malware is not)
- CVEs affecting AI agent frameworks and tools
- Research papers and credible write-ups
- Defensive tools and mitigations

## What does NOT belong here

- Working malware or active C2 infrastructure
- Unverified rumors without any supporting evidence
- Theoretical attacks with no practical basis
- Vendor FUD or marketing content

## How to submit

1. Fork the repo
2. Add your entry in the appropriate section
3. Use this format for incidents:

```markdown
### Incident Name (Month Year)

Short description of what happened.

**Attack vector:** ...
**Impact:** ...
**Why it worked:** ...
**References:** links to reports, CVEs, or write-ups
```

4. Mark unverified or theoretical entries with `[unverified]`
5. Open a PR with a brief description

## Labeling conventions

| Label | Meaning |
|-------|---------|
| `[verified]` | Confirmed real incident with public references |
| `[unverified]` | Reported but not independently confirmed |
| `[theoretical]` | Demonstrated in research / lab setting, no confirmed wild exploitation |
| `[patched]` | Vulnerability fixed in a released version |

## Code of conduct

This project documents attacks for defensive purposes. Do not use anything here to harm others.
