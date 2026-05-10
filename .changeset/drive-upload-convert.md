---
"@googleworkspace/cli": minor
---

Add `--convert` flag to `gws drive +upload`. When set, `.docx`/`.xlsx`/`.pptx` files are uploaded as their Google native equivalents (Doc/Sheet/Slides) via Drive's built-in transcoding. Pairs with three new bridge recipes (`recipe-create-formatted-doc`, `recipe-create-formatted-sheet`, `recipe-create-formatted-slides`) that compose Anthropic's `document-skills` with Drive upload to produce properly-formatted Google Workspace artifacts instead of plain-text dumps.
