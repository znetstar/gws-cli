---
description: Today's meetings + open tasks as a standup summary
argument-hint: [extra flags passed through to gws workflow +standup-report]
allowed-tools: Bash(gws workflow +standup-report:*)
---

Run the standup-report workflow and format the result as a 3-section message the user can paste into Slack/Chat:

1. **Yesterday** — completed tasks (if the workflow surfaces them)
2. **Today** — meetings and active tasks
3. **Blockers** — anything overdue or stuck

Keep it terse. No filler.

!`gws workflow +standup-report $ARGUMENTS`
