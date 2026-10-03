#!/usr/bin/env python3
"""A broken core: prints credential-shaped garbage to stderr and exits 1.

Used to assert that startup failures are detected AND redacted.
"""
import sys

print("password=super-secret-value-123456 uuid=b831381d-6324-4d53-ad4f-8cda48b30811")
print("vless-scheme-example-b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443", file=sys.stderr)
sys.exit(1)
