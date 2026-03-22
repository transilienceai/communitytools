#!/usr/bin/env python3
"""Send messages to Slack channels.

Usage:
    # Simple message
    python3 tools/slack-send.py --token xoxb-... --channel C0XXXXXX "Deployment complete"

    # Read message from stdin (useful for multi-line)
    printf '*Bold title*\n- item 1\n- item 2' | python3 tools/slack-send.py --token xoxb-... --channel C0XXXXXX -

    # Read message from file
    python3 tools/slack-send.py --token xoxb-... --channel C0XXXXXX --file message.txt

    # Reply in thread
    python3 tools/slack-send.py --token xoxb-... --channel C0XXXXXX --thread-ts 1234567890.123456 "Thread reply"

Slack mrkdwn formatting:
    *bold*  _italic_  ~strikethrough~  `code`  ```code block```
    > blockquote    - bullet list    1. numbered list
    <url|display text>  :emoji:

Exit codes: 0 = sent, 2 = API error, 3 = usage error
"""

import argparse
import json
import sys
import urllib.request
import urllib.error


def send_message(token: str, channel: str, text: str, thread_ts: str | None = None) -> dict:
    payload = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Send a message to a Slack channel")
    parser.add_argument("--token", required=True, help="Slack Bot Token (xoxb-...)")
    parser.add_argument("--channel", required=True, help="Slack channel ID")
    parser.add_argument("--thread-ts", help="Thread timestamp to reply to")
    parser.add_argument("--file", help="Read message from file instead of argument")
    parser.add_argument("message", nargs="?", help='Message text (use "-" to read from stdin)')
    args = parser.parse_args()

    # Resolve message text
    if args.file:
        with open(args.file) as f:
            text = f.read().strip()
    elif args.message == "-":
        text = sys.stdin.read().strip()
    elif args.message:
        text = args.message
    else:
        parser.error("Provide a message, --file, or use '-' for stdin")

    if not text:
        print("SLACK_ERROR: empty message", file=sys.stderr)
        sys.exit(3)

    # Send
    result = send_message(args.token, args.channel, text, args.thread_ts)
    if result.get("ok"):
        ts = result.get("ts", "")
        print(f"SLACK_SENT: to {args.channel} (ts={ts})")
        sys.exit(0)
    else:
        print(f"SLACK_ERROR: {result.get('error', 'unknown')}")
        sys.exit(2)


if __name__ == "__main__":
    main()
