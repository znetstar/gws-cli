---
name: recipe-create-formatted-slides
description: "Create a Google Slides deck with real layouts, colors, and typography by building a .pptx via document-skills:pptx then…"
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

# Create a Properly-Formatted Google Slides Deck

> **PREREQUISITE:** Load the following skills to execute this recipe: `gws-drive`

Create a Google Slides deck with real layouts, colors, and typography by building a .pptx via document-skills:pptx then uploading with conversion.

> [!CAUTION]
> Drive transcoding preserves slide layout, text, basic shapes, and standard fonts. Animations, transitions, custom-embedded fonts, and some advanced effects may not survive the conversion. For simple title-only presentations, the existing `recipe-create-presentation` is lighter weight.

## Steps

1. Invoke the `document-skills:pptx` skill to build the deck. Have it save the .pptx to a temp path you control, e.g. `/tmp/<slug>.pptx`. The skill generates slides with proper layouts, bold color palettes, and typography pairings via PptxGenJS.
2. Upload with conversion: `gws drive +upload /tmp/<slug>.pptx --convert` (add `--parent FOLDER_ID` to drop into a folder; add `--name 'Final Title'` to override the filename).
3. Return the resulting `id` and `webViewLink` from the response. Spot-check the converted deck — surface any drift (missing fonts, dropped animations) to the user.

