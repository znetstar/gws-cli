---
description: Clear local gws credentials and token caches
allowed-tools: Bash(gws auth logout)
---

Run `gws auth logout` to clear all local credential and token cache files. If the user has `GOOGLE_WORKSPACE_CLI_OP_ITEM` set, remind them this only clears the local cache — the 1Password item itself must be deleted with `op item delete`.

!`gws auth logout`
