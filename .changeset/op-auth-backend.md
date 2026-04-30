---
"@googleworkspace/cli": minor
---

Add 1Password as an auth backend. Set `GOOGLE_WORKSPACE_CLI_OP_ITEM` (and `OP_VAULT` when the reference is bare) to fetch credentials directly from a 1Password item — no more `op run --` wrapper. `gws auth login --1password --vault <v>` runs the OAuth flow and writes the resulting refresh token to a new 1Password item; `gws auth setup --1password` lists vaults to pick from. Both desktop-app integration and `OP_SERVICE_ACCOUNT_TOKEN` are supported via the `op` CLI.
