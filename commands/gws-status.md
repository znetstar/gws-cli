---
description: Show current gws auth status (account, scopes, backend)
allowed-tools: Bash(gws auth status:*)
---

Run `gws auth status` and summarize the result for the user. Highlight:

- Active auth method (oauth2, 1password, or none)
- Account email if known
- Whether the access token is currently valid
- Number of granted scopes
- Any errors

!`gws auth status`
