---
name: recipe-create-formatted-doc
description: "Create a Google Doc with real formatting (headings, lists, tables, images) by drafting via document-skills:docx then…"
metadata:
  version: 0.22.5
  openclaw:
    category: "recipe"
    domain: "productivity"
    requires:
      bins:
        - gws
      skills:
        - gws-drive
---

# Create a Properly-Formatted Google Doc

> **PREREQUISITE:** Load the following skills to execute this recipe: `gws-drive`

Create a Google Doc with real formatting (headings, lists, tables, images) by drafting via document-skills:docx then uploading with conversion.

> [!CAUTION]
> Drive transcodes the .docx into a Google Doc once at upload. Subsequent edits go through `gws docs batchUpdate`, not the source file. For purely plain-text writes to an existing Doc, use `gws-docs-write` instead.

## Steps

1. Invoke the `document-skills:docx` skill to draft the document. Have it save the .docx to a temp path you control, e.g. `/tmp/<slug>.docx`. The skill produces real Word XML with headings, bold, bullets, tables, and images — formatting that Drive's transcoding preserves.
2. Upload with conversion: `gws drive +upload /tmp/<slug>.docx --convert` (add `--parent FOLDER_ID` to drop into a folder; add `--name 'Final Title'` to override the filename).
3. Return the resulting `id` and `webViewLink` from the response so the user can open the new Google Doc.

