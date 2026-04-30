---
description: Convert a Gmail message into a Google Tasks entry
argument-hint: <gmail-message-id> [extra flags]
allowed-tools: Bash(gws workflow +email-to-task:*)
---

Convert the specified Gmail message into a task. Required: a `--message-id <ID>` value (or pass it as the first argument).

If `$ARGUMENTS` looks like a bare message id (no `--`), pass it as `--message-id`. Otherwise pass through unchanged.

!`if [[ "$ARGUMENTS" =~ ^- ]] || [ -z "$ARGUMENTS" ]; then gws workflow +email-to-task $ARGUMENTS; else gws workflow +email-to-task --message-id "$ARGUMENTS"; fi`

Confirm the created task back to the user with its title, due date (if any), and the link to it.
