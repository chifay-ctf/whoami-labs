#!/usr/bin/env python3
import base64

encoded = "TG8gc2llbnRvLCBwb3Igbm8gcG9kZXIgZGFydGUgcGlzdGFzIHNvYnJlIGVsIGxhYm9yYXRvcmlvLCBwZXJvIGRlIHRvZGFzIGZvcm1hcyB5YSBhcHJlbmRpc3RlIGFsZ28gbnVldm8hISEgCgpQNzAwMywgUDcwMDUsIFA3MDA3"

decoded = base64.b64decode(encoded).decode("utf-8")
print(decoded)
