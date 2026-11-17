# Result format and reporting

Unified CLI output is a JSON object with `schema_version: 1`, `tool: "pentestlab"`, package version, timezone-qualified `timestamp_utc`, command, target, options, status (`ok`/`error`), observations and an array of error strings. Each invocation has a new timestamp; these envelopes are not byte-identical across runs. The observation content can still be compared independently.

The schema version identifies the outer envelope. Observation payloads are command-specific: scan returns hosts and port states, headers returns HTTP status and header pairs, and pcap returns SSIDs. Offline scan options are marked `mode: offline-xml`; live scan settings are not falsely reported as applied to a previously captured XML file.

`pentestlab report first.json second.json --output report.md` validates envelopes before creating a new file. Legacy script JSON is not automatically treated as a versioned observation. Report text confines source data to sufficiently long fenced JSON blocks, including values containing backticks or HTML. Reports do not fetch links, execute content, label open ports as vulnerabilities, or assess header policy completeness.

Operational failures produce status `error` and exit 2. Argument failures or inability to write output are reported on stderr. Existing output files are rejected before active operations; exclusive creation also prevents overwrites during a race. There is no implicit directory creation or partial report written for invalid inputs. An HTTP 4xx/5xx response is a successfully observed HTTP result, not necessarily a CLI transport failure.

Reports can contain hostnames, URLs and response headers. Review them before sharing. Automatic sensitive-header redaction and cryptographic result signatures are outside this version's scope.
