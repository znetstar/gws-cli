---
name: recipe-create-formatted-sheet
description: "Create a Google Sheet with formulas, headers, and formatting by building a .xlsx via document-skills:xlsx then…"
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

# Create a Properly-Formatted Google Sheet

> **PREREQUISITE:** Load the following skills to execute this recipe: `gws-drive`

Create a Google Sheet with formulas, headers, and formatting by building a .xlsx via document-skills:xlsx then uploading with conversion.

> [!CAUTION]
> Drive transcodes the .xlsx into a Google Sheet once at upload. Subsequent edits go through the Sheets API (`gws sheets +append`, etc.), not the source file. For appending rows to an existing Sheet, use `gws-sheets-append` instead.

## Steps

1. Invoke the `document-skills:xlsx` skill to build the spreadsheet. Have it save the .xlsx to a temp path you control, e.g. `/tmp/<slug>.xlsx`. The skill handles formulas, headers, number formatting, and color-coded conventions; it also runs a recalculation step to catch formula errors before delivery.
2. Upload with conversion: `gws drive +upload /tmp/<slug>.xlsx --convert` (add `--parent FOLDER_ID` to drop into a folder; add `--name 'Final Title'` to override the filename).
3. Return the resulting `id` and `webViewLink` from the response. Formulas evaluate live in Google Sheets after the conversion.

