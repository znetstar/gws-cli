---
description: Show unread Gmail summary (sender, subject, date)
argument-hint: [extra flags passed through to gws gmail +triage]
allowed-tools: Bash(gws gmail +triage:*)
---

Run the Gmail triage helper to show the user's unread messages. Present the result grouped by sender if there are repeats, oldest first. Suggest follow-up actions (reply, archive, label) for items that look time-sensitive.

!`gws gmail +triage $ARGUMENTS`
