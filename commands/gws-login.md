---
description: Run the gws auth login flow (OAuth in browser)
argument-hint: [--readonly|--full|--scopes <list>] [--1password --vault <v>]
allowed-tools: Bash(gws auth login:*)
---

Run `gws auth login` with any flags the user passed. After the flow completes, parse the JSON output and report:

- Account email
- Where credentials were saved (encrypted file path or 1Password item)
- Granted scopes

If the user did not pass `--1password` and they appear to have `GOOGLE_WORKSPACE_CLI_OP_ITEM` configured in their environment, mention that they may want `--1password --vault <vault>` to keep the refresh token in 1Password instead of `credentials.enc`.

!`gws auth login $ARGUMENTS`
