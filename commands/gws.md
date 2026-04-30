---
description: Show the gws plugin landing page (auth status + available commands)
allowed-tools: Bash(gws auth status), Bash(gws --help)
---

Show the user a quick orientation to the gws plugin.

Run `gws auth status` to surface the current auth state, then list the commands this plugin provides, grouped:

**Auth & quick views**
- `/gws-status` — current auth state
- `/gws-login [flags]` — OAuth login (use `--1password --vault <v>` to store in 1Password)
- `/gws-logout` — clear local credentials
- `/gws-agenda` — today's calendar across all calendars
- `/gws-inbox` — unread Gmail summary

**Workflows**
- `/gws-meeting-prep` — next meeting brief
- `/gws-standup` — today's meetings + tasks as a standup
- `/gws-weekly-digest` — this week summary
- `/gws-email-to-task <message-id>` — convert email to task
- `/gws-announce-file --file-id <id> --space <space>` — post Drive file to Chat

**Personas** (load a role for the rest of the session)
- `/gws-as-event-coordinator`, `/gws-as-exec-assistant`, `/gws-as-sales-ops`,
  `/gws-as-team-lead`, `/gws-as-it-admin`, `/gws-as-customer-support`,
  `/gws-as-content-creator`, `/gws-as-researcher`, `/gws-as-project-manager`,
  `/gws-as-hr-coordinator`

**Skills** (95 total, auto-activated by request keywords) cover Drive, Gmail, Calendar, Docs, Sheets, Slides, Tasks, Chat, Meet, Forms, Keep, Classroom, People, Admin Reports, Vault, Model Armor, plus end-to-end recipes.

!`gws auth status`
