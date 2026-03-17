# Generating Panels Skill

Generates manga-style comic panels via the Google Gemini API (v1beta) using curl.

## Quick Start

1. Set `GOOGLE_API_KEY` environment variable
2. The comic-artist agent invokes this skill for each panel
3. Each call produces one PNG image from a text prompt

## How It Works

1. Assembles prompt: style block + scene description + character bible + negative prompts
2. Writes JSON payload to `/tmp/gemini_panel_request.json`
3. Calls Gemini API via curl
4. Extracts base64 image data from response with jq
5. Decodes to PNG at the specified output path
6. Verifies file exists and is >10KB

## API Details

- **Model**: `gemini-2.0-flash-exp`
- **Endpoint**: `generativelanguage.googleapis.com/v1beta`
- **Method**: `generateContent` with `responseModalities: ["TEXT", "IMAGE"]`

## Dependencies

- `curl` — HTTP client
- `jq` — JSON processing
- `base64` — binary decode

## Reference Files

- `reference/GEMINI-API.md` — API endpoint and payload structure
- `reference/PROMPT-ENGINEERING.md` — Prompt construction guidelines
- `reference/QUALITY-CRITERIA.md` — Evaluation criteria for generated panels
