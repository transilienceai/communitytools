---
name: generating-panels
description: Generate manga-style comic panels via Google Gemini API using curl
---

# Skill: Generating Panels — Gemini API Image Generation

## Purpose

Generate manga-style comic panels via the Google Gemini API using curl. Each invocation produces one panel image from a text prompt.

## Prerequisites

- `GOOGLE_API_KEY` environment variable must be set
- `curl`, `jq`, `base64` available in PATH

## Input

The caller provides:
- `PROMPT` — Full assembled text prompt (style + scene + character + negative prompts)
- `OUTPUT_PATH` — Destination file path for the generated PNG
- `ASPECT_RATIO` — Either "16:9" or "3:4"

## Workflow

### 1. Validate Environment

```bash
if [ -z "$GOOGLE_API_KEY" ]; then
  echo "ERROR: GOOGLE_API_KEY not set"
  exit 1
fi
```

### 2. Build JSON Payload

Write the request payload to a temp file to avoid shell escaping issues:

```bash
cat > /tmp/gemini_panel_request.json << 'JSONEOF'
{
  "contents": [
    {
      "parts": [
        {
          "text": "<ASSEMBLED_PROMPT>"
        }
      ]
    }
  ],
  "generationConfig": {
    "responseModalities": ["TEXT", "IMAGE"],
    "temperature": 1.0
  }
}
JSONEOF
```

### 3. Prompt Assembly

Assemble prompt in order: Style Block → Scene Description (from `panels.md`) → Character Block (from `characters.md`) → Technical Directives (aspect ratio + NO text) → Negative Prompt Block. See `reference/PROMPT-ENGINEERING.md` for full details on each section.

### 4. Execute API Call

```bash
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image:generateContent?key=$GOOGLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d @/tmp/gemini_panel_request.json)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "$BODY" > /tmp/gemini_response.json
```

### 5. Handle Errors

```bash
# Rate limit
if [ "$HTTP_CODE" = "429" ]; then
  echo "Rate limited. Waiting 30s..."
  sleep 30
  # Retry (max 2 retries)
fi

# Network error
if [ "$HTTP_CODE" = "000" ]; then
  echo "Network error. Retrying in 5s..."
  sleep 5
  # Retry once
fi

# API error
if [ "$HTTP_CODE" != "200" ]; then
  echo "API error $HTTP_CODE:"
  cat /tmp/gemini_response.json | jq '.error' 2>/dev/null
  exit 1
fi
```

### 6. Extract Image Data

```bash
IMAGE_DATA=$(jq -r '.candidates[0].content.parts[] | select(.inlineData) | .inlineData.data' /tmp/gemini_response.json)

if [ -z "$IMAGE_DATA" ] || [ "$IMAGE_DATA" = "null" ]; then
  echo "ERROR: No image data in response"
  echo "Response text:"
  jq -r '.candidates[0].content.parts[] | select(.text) | .text' /tmp/gemini_response.json
  exit 1
fi
```

### 7. Decode and Save

```bash
echo "$IMAGE_DATA" | base64 -d > "$OUTPUT_PATH"
```

### 8. Verify Output

```bash
FILE_SIZE=$(wc -c < "$OUTPUT_PATH")
if [ "$FILE_SIZE" -lt 10240 ]; then
  echo "WARNING: Output file suspiciously small (${FILE_SIZE} bytes)"
  exit 1
fi

echo "SUCCESS: Panel saved to $OUTPUT_PATH (${FILE_SIZE} bytes)"
file "$OUTPUT_PATH"
```

## Error Recovery

| Error | Action |
|-------|--------|
| 429 Rate Limit | `sleep 30`, retry (max 2) |
| Network failure | `sleep 5`, retry once |
| No image in response | Log response text, return failure |
| File <10KB | Treat as generation failure, return failure |
| Invalid JSON | Log raw response, return failure |

## Output

- Generated PNG at `$OUTPUT_PATH`
- Success/failure message to stdout
- On failure: error details to stderr

## Notes

- Model `gemini-2.5-flash-image` supports image generation via `responseModalities: ["TEXT", "IMAGE"]`
- Payload written to temp file to avoid shell escaping issues with complex prompts
- Base64 decode: `base64 -d` on macOS, `base64 --decode` on Linux
