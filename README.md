# livesub

`livesub` is a Python command-line tool that runs ProjectDiscovery `subfinder`, probes discovered names with ProjectDiscovery `httpx`, and writes grouped text and JSON reports. It is intended for authorized pentesting and bug bounty work.

## Requirements

- Python 3.9 or newer
- ProjectDiscovery [subfinder](https://github.com/projectdiscovery/subfinder)
- ProjectDiscovery [httpx](https://github.com/projectdiscovery/httpx)

Install the scanners with Go:

```sh
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure the Go `bin` directory is on your `PATH`. `livesub` has no Python runtime dependencies. It checks that `httpx` exposes ProjectDiscovery's scanner flags before it starts; some systems also have an unrelated Python CLI named `httpx`. If needed, specify the scanner directly with `--httpx-bin /path/to/httpx` or `LIVESUB_HTTPX_BIN`.

## Install

Install the published package:

```sh
python -m pip install livesub
```

Or install from a source checkout:

```sh
python -m pip install .
```

You can also run `./livesub` directly from a checkout without installing the Python package.

## Usage

```text
livesub [OPTIONS] <domain>
```

Examples:

```sh
livesub example.com
livesub -o ./results example.com
livesub -o ./results -t 40 -timeout 8 example.com
livesub -silent example.com
livesub --httpx-bin "$HOME/go/bin/httpx" example.com
```

Options:

| Option | Description |
| --- | --- |
| `-o <dir>` | Output directory. Defaults to `./reconchain_<domain>_<timestamp>`. |
| `-t <n>` | Thread count passed to both scanners. |
| `-timeout <seconds>` | Per-request timeout passed to httpx. Defaults to 10 seconds. |
| `-silent` | Suppress progress messages and print only the final summary. |
| `--subfinder-bin <path>` | Select a non-default subfinder executable. |
| `--httpx-bin <path>` | Select ProjectDiscovery httpx explicitly. |
| `-h`, `--help` | Show usage information. |
| `--version` | Show the livesub version. |

## Output

The output directory contains:

- `subdomains.txt`: raw subfinder results.
- `live_hosts.txt`: raw httpx JSONL results with status, title, and technology detection enabled.
- `summary.txt`: Markdown report grouped and sorted by HTTP status code.
- `summary.json`: machine-readable report with the same status groups and status-family counts.

Example final stdout summary:

```text
Summary: 42 subdomains found, 17 live | 2xx: 11, 3xx: 2, 4xx: 3, 5xx: 1
```

Use this only for domains you own or have explicit permission to assess.
