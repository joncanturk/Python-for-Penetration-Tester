# Changelog

## 0.2.0 — Unified interface

- Installable package and `pentestlab scan`, `headers`, `pcap`, `report` commands.
- Versioned JSON observation envelopes and validated Markdown reports.
- Exclusive output creation and structured operational failures.
- Real ephemeral-loopback HTTP/TCP integration tests and installed-command CI checks.
- Three documented lab workflows; legacy entry points remain compatible.

## Unreleased — 2026-11-17

- Python 3.11+ entry points, side-effect-free imports and argparse help throughout.
- Nmap XML output, single bounded invocation, input validation and offline inspection.
- MD5 matching preserves candidate whitespace, supports empty matches, stops early and retains legacy flags.
- HTTP HEAD inspection with timeout, no redirects and no implicit geolocation lookup.
- Local-only screenshot capture with no embedded FTP credentials.
- Correct unicast/local MAC generation, explicit Linux application and shared compatibility entry point.
- Loopback-only single-client server with resource cleanup and timeouts.
- Offline packet construction and 802.11 SSID analysis replace automatic packet sending and monitor-mode changes.
- Offline regression tests, synthetic examples and Windows/Linux CI.
