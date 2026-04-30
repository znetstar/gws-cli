---
description: Announce a Drive file in a Chat space
argument-hint: --file-id <ID> --space <SPACE> [extra flags]
allowed-tools: Bash(gws workflow +file-announce:*)
---

Run the file-announce workflow. The user must supply at least `--file-id` and `--space`; if either is missing, ask before running.

!`gws workflow +file-announce $ARGUMENTS`

After the announcement is posted, confirm to the user with the Chat message URL and the file title.
