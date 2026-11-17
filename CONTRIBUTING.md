# Contributing

Use Python 3.11+ and run `python -m unittest discover -s tests -v`. Install `requirements-pcap.txt` to include the offline Scapy tests. Keep optional dependencies inside the functions that use them so all CLI help and imports work without desktop or packet libraries.

Each behavioral change should include success and failure tests. Use synthetic fixtures, temporary files and mocked network/process interfaces. Never run active scans, packet transmission, live screen capture or interface changes in CI.

Retain source filenames where possible and document compatibility changes. New flags must make external side effects explicit.
