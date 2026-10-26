---
"@googleworkspace/cli": patch
---

Fix `gws auth login --1password` overwriting the stored `project_id` with an empty value, which caused later runs to fall back to the default gcloud project
