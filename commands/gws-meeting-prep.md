---
description: Prepare for next meeting — agenda, attendees, linked docs
argument-hint: [extra flags passed through to gws workflow +meeting-prep]
allowed-tools: Bash(gws workflow +meeting-prep:*)
---

Run the meeting-prep workflow to gather everything needed for the user's next meeting. Surface in the response:

- Meeting title and start time
- Attendees with display names
- Any linked Google Docs / Sheets / Slides (open them via `gws drive files get` if titles aren't obvious)
- Suggested talking points based on the agenda or doc contents

!`gws workflow +meeting-prep $ARGUMENTS`
