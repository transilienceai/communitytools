# Gemini API Reference — Image Generation

## Endpoint

```
POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image:generateContent?key=$GOOGLE_API_KEY
```

## Request Headers

```
Content-Type: application/json
```

## Request Payload

```json
{
  "contents": [
    {
      "parts": [
        {
          "text": "Your image generation prompt here"
        }
      ]
    }
  ],
  "generationConfig": {
    "responseModalities": ["TEXT", "IMAGE"],
    "temperature": 1.0
  }
}
```

### Key Fields

| Field | Value | Purpose |
|-------|-------|---------|
| `responseModalities` | `["TEXT", "IMAGE"]` | Enable image generation output |
| `temperature` | `1.0` | Maximum creative variation |
| `contents.parts.text` | Prompt string | Full assembled generation prompt |

## Response Structure

```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "Description of generated image..."
          },
          {
            "inlineData": {
              "mimeType": "image/png",
              "data": "<base64-encoded-image-data>"
            }
          }
        ]
      }
    }
  ]
}
```

### Extracting Image Data

```bash
jq -r '.candidates[0].content.parts[] | select(.inlineData) | .inlineData.data' response.json
```

### Extracting Text Response

```bash
jq -r '.candidates[0].content.parts[] | select(.text) | .text' response.json
```

## HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Extract image data |
| 400 | Bad request | Check payload structure |
| 403 | Forbidden | Check API key validity |
| 429 | Rate limited | Wait 30s, retry (max 2) |
| 500 | Server error | Retry once after 5s |

## Rate Limits

- Free tier: ~15 requests per minute
- Implement backoff: 30s on 429, max 2 retries per request
- Space requests ~5s apart for sustained generation runs

## Notes

- The model returns both text and image in the same response
- Image data is base64-encoded PNG
- Large prompts (>4000 chars) are fine — the model handles long context
- Use temp file for payload to avoid shell escaping: `-d @/tmp/payload.json`
