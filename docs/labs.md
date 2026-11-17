# Local lab workflows

Install from the repository with `python -m pip install ".[pcap]"`. Work only on services and captures you own or are authorized to assess. Use new output names for each run.

## 1. Service observation

For a manual TCP exercise, run `python server.py --port 9337 --timeout 60` in one terminal. From another terminal, `pentestlab scan 127.0.0.1 --ports 9337 --timeout 10 --output service.json` uses an installed Nmap executable. The greeting server handles only one connection, so it exits after Nmap's connection; restart for each run. An open port shows reachability, not a vulnerability.

For a deterministic offline alternative:

```sh
pentestlab scan --xml examples/nmap.xml --output offline-scan.json
pentestlab report offline-scan.json --output offline-report.md
```

## 2. HTTP observation and reporting

Create an empty temporary directory and start `python -m http.server 8765 --bind 127.0.0.1 --directory PATH_TO_EMPTY_DIRECTORY`. Choose another port if occupied; do not stop someone else's service. Then run:

```sh
pentestlab headers http://127.0.0.1:8765 --output headers.json
pentestlab report offline-scan.json headers.json --output combined-report.md
```

Stop the manual HTTP server with Ctrl+C when finished. The tool reports observed headers; it does not grade their security or follow redirects. Missing headers require application-specific analysis.

## 3. Packet construction and capture inspection

`python floodz.py --output sample.pcap --count 5` creates five synthetic Ethernet/IP/TCP packets without transmission. Inspect this file in your packet viewer. The SSID subcommand expects an authorized **802.11** capture instead, for example `pentestlab pcap lab-wireless.pcap --output ssids.json`. An Ethernet/TCP sample contains no SSIDs and yields an empty list, which is expected.

## Automated reproduction

`python -m unittest discover -s tests -v` starts and cleans up its own HTTP/TCP services on ephemeral loopback ports. It verifies a real HEAD response, redirect suppression, report generation and a real TCP greeting, in addition to offline/unit checks. It does not use any pre-existing browser tab or service. Nmap itself remains mocked in tests; an actual scanner integration is not claimed.
