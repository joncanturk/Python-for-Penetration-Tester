# Python for Penetration Testers

Small, inspectable Python tools for authorized security labs. Every script has a CLI, clear errors and no work performed merely by importing it.

## Requirements

- Python 3.11+; core tools and all `--help` commands need no third-party Python libraries.
- Nmap on PATH for live scans; XML inspection works offline without Nmap.
- PCAP tools: `python -m pip install -r requirements-pcap.txt`.
- Screenshot tool: `python -m pip install -r requirements-desktop.txt` plus a supported desktop session.
- Applying a MAC requires Linux, iproute2 and suitable privileges; generation works across platforms.

Use `python -m venv .venv` and activate the environment before installing optional dependencies.

## Start offline

```sh
python -m unittest discover -s tests -v
python nmapscanner.py --xml examples/nmap.xml
python md5crack.py -md5 5d41402abc4b2a76b9719d911017c592 -w examples/words.txt
python new_mac.py
```

The MD5 example returns `{"matched": true, "value": "hello"}`. The XML fixture contains one up host with TCP/22 open, aggregated closed ports, and one down host. `--xml` never starts a scan.

## Tools

| Script | Example | Behavior |
|---|---|---|
| `nmapscanner.py` | `python nmapscanner.py 127.0.0.1 --ports 22,80 --timeout 10` | One bounded Nmap TCP-connect scan; JSON output |
| `inforecon.py` | `python inforecon.py http://127.0.0.1:8000 --timeout 5` | One HEAD request; reports redirects without following them |
| `md5crack.py` | See quick start | Offline wordlist matching; preserves candidate whitespace |
| `macspoofpy.py` | `python macspoofpy.py` | Generates a locally administered unicast MAC |
| `new_mac.py` | `python new_mac.py` | Compatibility alias using the same implementation |
| `server.py` | `python server.py --port 9337 --timeout 15` | One-client loopback greeting server; bounded wait |
| `grabber.py` | `python grabber.py --output capture.png` | Local PNG only; no upload |
| `floodz.py` | `python floodz.py --output sample.pcap --count 5` | Offline synthetic PCAP; no packets sent |
| `hiddenwifi.py` | `python hiddenwifi.py lab-wireless.pcap` | Read SSIDs from an existing authorized 802.11 capture |

Every script supports `--help`. PCAP/PNG output files must not already exist. Nmap accepts one IP or hostname and at most 100 comma-separated ports; ranges and arbitrary Nmap options are rejected. IPv6 literals enable IPv6 scanning. Hostname resolution follows the system/Nmap environment; verify assessment scope before use.

SSID extraction uses the SSID information element, omits empty hidden names, deduplicates results and replaces invalid UTF-8. Names absent from the capture cannot be recovered.

## Compatibility changes

- Filenames and MD5 `-md5`/`-w` flags are retained. All import-time execution is removed.
- `floodz.py` now constructs a bounded teaching PCAP instead of sending packets to a fixed external address.
- `hiddenwifi.py` reads PCAP input instead of altering monitor mode or sniffing indefinitely.
- `grabber.py` requires an output filename; embedded FTP credentials and uploads are removed.
- MAC changes require `--apply --interface NAME`. The original up/down state is restored after the address-change attempt; failures are surfaced. Applying can interrupt connectivity and does not restore the previous MAC automatically.
- HTTP inspection requires a full HTTP(S) URL, issues HEAD, reports error/redirect statuses in JSON and makes no geolocation call. It does not retry with GET. System proxy settings still apply.
- Nmap uses a single executable invocation and its XML interface instead of repeated per-port calls through python-nmap. Aggregated port states are retained without inventing per-port results.

## Testing and limits

```sh
python -m pip install -r requirements-pcap.txt
python -m unittest discover -s tests -v
```

The suite contains 19 tests, including two optional Scapy tests. CI installs Scapy and runs Windows/Ubuntu with Python 3.11/3.13. Coverage includes imports/help, argument validation, MD5 edge cases, Nmap XML and timeout errors, HTTP behavior, MAC state restoration, socket cleanup, PCAP generation and SSID layers.

Network/system effects are mocked. Live scans, screenshots, monitor-mode capture and privileged interface changes are not exercised. Desktop and hardware behavior require separate environment-specific validation. MD5 matching is educational; MD5 is unsuitable for password storage. XML/PCAP parsing is intended for small lab inputs, not a hardened public ingestion service.

Exit status: 0 for completion, 2 for usage/operational errors; MD5 also returns 1 for no match. No hosts in Nmap output is a valid result, not automatically an error.

## References and maintenance

- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [Scapy capture handling](https://scapy.readthedocs.io/en/latest/usage.html)
- [Python subprocess API](https://docs.python.org/3/library/subprocess.html)
- [wxPython image API](https://docs.wxpython.org/wx.Image.html)
- [Change log](CHANGELOG.md), [contributing](CONTRIBUTING.md), [security policy](SECURITY.md)

No license grant is added by this change; the owner should choose a license before inviting reuse. Optional dependency ranges are not a reproducible lockfile.
