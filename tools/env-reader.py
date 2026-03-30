#!/usr/bin/env python3
"""Read .env variables without shell sourcing.

Usage:
    python3 tools/env-reader.py VAR1 VAR2 VAR3    # specific variables
    python3 tools/env-reader.py all                # all variables

Output:
    ENV_STATUS:            (safe for logging — sensitive values masked)
    HTB_USER=someone@email.com
    HTB_PASS=<SET> (length: 24)

    ENV_VALUES:            (actual values — use these)
    HTB_USER=someone@email.com
    HTB_PASS=actualpassword123

Exit codes: 0 = found at least one, 1 = all NOT_SET or no .env found
"""

import os
import sys

SEARCH_PATHS = [
    os.path.join(os.getcwd(), ".env"),
    os.path.join(os.getcwd(), "projects/pentest/.env"),
    os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
]

SENSITIVE_KEYWORDS = ("PASS", "TOKEN", "KEY", "SECRET")


def parse_env_files() -> dict[str, str]:
    env = {}
    for path in SEARCH_PATHS:
        if os.path.isfile(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                        val = val[1:-1]
                    env[key] = val
    return env


def main():
    if len(sys.argv) < 2:
        print("Usage: env-reader.py VAR1 [VAR2 ...] | all", file=sys.stderr)
        sys.exit(2)

    env = parse_env_files()

    requested = sys.argv[1:]
    if len(requested) == 1 and requested[0].lower() == "all":
        requested = sorted(env.keys())

    print("ENV_STATUS:")
    for var in requested:
        val = env.get(var)
        if val is None:
            print(f"{var}=NOT_SET")
        elif any(kw in var.upper() for kw in SENSITIVE_KEYWORDS):
            print(f"{var}=<SET> (length: {len(val)})")
        else:
            print(f"{var}={val}")

    print()
    print("ENV_VALUES:")
    any_set = False
    for var in requested:
        val = env.get(var)
        if val is None:
            print(f"{var}=NOT_SET")
        else:
            print(f"{var}={val}")
            any_set = True

    sys.exit(0 if any_set else 1)


if __name__ == "__main__":
    main()
