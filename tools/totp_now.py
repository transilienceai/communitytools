#!/usr/bin/env python3
"""Dependency-free RFC 6238 TOTP / RFC 4226 HOTP generator (stdlib only).

Gives the `authenticated-session-acquisition` skill a concrete, deterministic
"TOTP-from-seed" mode without pulling in pyotp/oathtool.

    totp_now.py <BASE32_SECRET> [--at UNIX] [--step 30] [--digits 6]
                [--digest sha1|sha256|sha512]

Prints just the current one-time code. Exit 0 ok / 2 usage.
"""
import argparse
import base64
import hashlib
import hmac
import struct
import sys
import time

_DIGESTS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def _now():
    """Time seam (seconds since epoch) so tests can inject a fixed clock."""
    return int(time.time())


def hotp(secret_bytes, counter, digits=6, digest="sha1"):
    """RFC 4226 HOTP for a raw secret and integer counter."""
    try:
        hasher = _DIGESTS[digest]
    except KeyError:
        raise ValueError(f"unsupported digest: {digest!r}")
    mac = hmac.new(secret_bytes, struct.pack(">Q", counter), hasher).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def _b32decode(secret_b32):
    """Base32-decode a shared secret, tolerating lowercase, spaces, missing pad."""
    cleaned = "".join(secret_b32.split()).upper()
    padding = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * padding)


def totp(secret_b32, at_unix=None, step=30, t0=0, digits=6, digest="sha1"):
    """RFC 6238 TOTP for a base32 secret at a given (or current) unix time."""
    if at_unix is None:
        at_unix = _now()
    counter = (int(at_unix) - t0) // step
    return hotp(_b32decode(secret_b32), counter, digits=digits, digest=digest)


def main(argv=None):
    parser = argparse.ArgumentParser(description="RFC 6238 TOTP code generator.")
    parser.add_argument("secret", help="base32-encoded shared secret")
    parser.add_argument("--at", type=int, default=None,
                        help="unix time to compute for (default: now)")
    parser.add_argument("--step", type=int, default=30, help="time step in seconds")
    parser.add_argument("--digits", type=int, default=6, help="number of code digits")
    parser.add_argument("--digest", choices=sorted(_DIGESTS), default="sha1",
                        help="HMAC digest algorithm")
    args = parser.parse_args(argv)
    print(totp(args.secret, at_unix=args.at, step=args.step,
               digits=args.digits, digest=args.digest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
