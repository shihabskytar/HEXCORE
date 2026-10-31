# HEXCORE Security & Privacy

## What HEXCORE does not do
- No licence cracking, DRM circumvention, key generation, trial manipulation, or patching.
- No credential theft, no stealth persistence, no exploitation of third-party systems.
- No automatic execution of unknown binaries. Dynamic analysis is consent-gated and refused by default.
- No upload of binaries to external services. The web UI talks only to localhost (127.0.0.1).

## Safe handling
- Analyse copies in an isolated VM, especially for unknown samples.
- The server binds to localhost only; do not expose it publicly or reverse-proxy it without authentication.
- Plugin permissions: plugins requesting `filesystem_write` or `execute` require `plugins_allow_sensitive=true` in config, otherwise they are not loaded.
- Malformed files are handled with try/except in parsers and with size/instruction limits; report a crash with the file hash (not the file itself) if you can reproduce it safely.

## Reporting a HEXCORE bug
Send a description, HEXCORE version, OS, and the smallest reproduction steps to the project maintainer (SKYTAR, https://www.shihabskytar.com). Do not send a live malware sample unsolicited; send hashes and a sanitised report first.
