"""Command-line implementation for livesub."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__


DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
SUBFINDER_INSTALL = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
HTTPX_INSTALL = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"


class LivesubError(Exception):
    """An error that should be shown without a Python traceback."""


class CommandError(LivesubError):
    """A failed external command and any relevant stderr output."""

    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr.strip()


def positive_int(value: str) -> int:
    try:
        number = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="livesub",
        description=(
            "Enumerate subdomains with ProjectDiscovery subfinder, probe them "
            "with ProjectDiscovery httpx, and write grouped reports."
        ),
        epilog="Use only for domains you own or are explicitly authorized to test.",
    )
    parser.add_argument(
        "-o", metavar="DIR", dest="outdir",
        help="output directory (default: ./reconchain_<domain>_<timestamp>)",
    )
    parser.add_argument(
        "-t", metavar="N", type=positive_int,
        help="thread count passed to subfinder and httpx (tool defaults if omitted)",
    )
    parser.add_argument(
        "-timeout", "--timeout", metavar="SECONDS", type=positive_int, default=10,
        help="per-request httpx timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-silent", action="store_true",
        help="suppress progress messages and print only the final summary",
    )
    parser.add_argument(
        "--subfinder-bin", default=os.environ.get("LIVESUB_SUBFINDER_BIN"),
        metavar="PATH", help="path/name of the subfinder executable",
    )
    parser.add_argument(
        "--httpx-bin", default=os.environ.get("LIVESUB_HTTPX_BIN"),
        metavar="PATH", help="path/name of ProjectDiscovery httpx (resolves name conflicts)",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__,
    )
    parser.add_argument("domain", help="target domain, such as example.com")
    return parser


def progress(silent: bool, message: str) -> None:
    if not silent:
        print("[*] " + message, file=sys.stderr)


def _resolve_executable(name_or_path: str, command_name: str) -> Optional[str]:
    """Resolve an executable name or explicit path and ensure it can be run."""
    expanded = os.path.expanduser(name_or_path)
    if os.path.dirname(expanded):
        candidate = os.path.abspath(expanded)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        return None
    return shutil.which(expanded or command_name)


def require_subfinder(requested: Optional[str]) -> str:
    executable = _resolve_executable(requested or "subfinder", "subfinder")
    if executable:
        return executable
    raise LivesubError(
        'Required tool "subfinder" is missing or not executable. Install it with:\n'
        "  " + SUBFINDER_INSTALL
    )


def _httpx_candidates(requested: Optional[str]) -> list[str]:
    if requested:
        resolved = _resolve_executable(requested, "httpx")
        return [resolved] if resolved else []

    candidates: list[str] = []
    seen: set[str] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory or os.curdir) / "httpx"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate.resolve())
            if resolved not in seen:
                seen.add(resolved)
                candidates.append(resolved)

    # Go's default install location is useful when it is not yet on PATH.
    go_default = Path.home() / "go" / "bin" / "httpx"
    if go_default.is_file() and os.access(go_default, os.X_OK):
        resolved = str(go_default.resolve())
        if resolved not in seen:
            candidates.append(resolved)
    return candidates


def _is_projectdiscovery_httpx(executable: str) -> bool:
    """Check for the distinctive PD flags before running any target probes."""
    try:
        result = subprocess.run(
            [executable, "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    help_text = result.stdout or ""
    return "-tech-detect" in help_text and "-status-code" in help_text


def require_httpx(requested: Optional[str]) -> str:
    candidates = _httpx_candidates(requested)
    for candidate in candidates:
        if _is_projectdiscovery_httpx(candidate):
            return candidate

    if requested and not candidates:
        detail = "The configured executable could not be found or is not executable."
    elif candidates:
        detail = (
            'An executable named "httpx" was found, but it does not expose the '
            "ProjectDiscovery -status-code and -tech-detect flags."
        )
    else:
        detail = 'The "httpx" executable was not found on PATH.'
    raise LivesubError(
        "Required tool ProjectDiscovery httpx is unavailable. " + detail + "\n"
        "Install it with:\n  " + HTTPX_INSTALL + "\n"
        "If it is installed elsewhere, pass --httpx-bin /path/to/httpx or set "
        "LIVESUB_HTTPX_BIN."
    )


def run_subfinder(
    executable: str,
    domain: str,
    threads: Optional[int],
    output_path: Path,
) -> None:
    command = [executable, "-d", domain, "-silent"]
    if threads is not None:
        command.extend(["-t", str(threads)])
    try:
        with output_path.open("w", encoding="utf-8", newline="") as output:
            result = subprocess.run(
                command,
                stdout=output,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                check=False,
            )
    except OSError as exc:
        raise CommandError("Could not start subfinder: " + str(exc)) from exc
    if result.returncode != 0:
        raise CommandError(
            "subfinder failed while enumerating " + domain + ".",
            result.stderr,
        )


def run_httpx(
    executable: str,
    threads: Optional[int],
    timeout: int,
    input_path: Path,
    output_path: Path,
) -> None:
    command = [
        executable,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-json",
    ]
    if threads is not None:
        command.extend(["-t", str(threads)])
    command.extend(["-timeout", str(timeout)])
    try:
        with input_path.open("r", encoding="utf-8") as source:
            with output_path.open("w", encoding="utf-8", newline="") as output:
                result = subprocess.run(
                    command,
                    stdin=source,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    check=False,
                )
    except OSError as exc:
        raise CommandError("Could not start ProjectDiscovery httpx: " + str(exc)) from exc
    if result.returncode != 0:
        raise CommandError("httpx failed while probing hosts.", result.stderr)


def count_nonempty_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="replace") as source:
        return sum(1 for line in source if line.strip())


def _hostname(record: dict[str, Any]) -> str:
    candidate = record.get("input") or record.get("host") or record.get("url") or ""
    hostname = str(candidate).strip()
    hostname = re.sub(r"^https?://", "", hostname, flags=re.IGNORECASE)
    hostname = hostname.split("/", 1)[0]
    hostname = re.sub(r":[0-9]+$", "", hostname)
    return hostname


def load_results(path: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LivesubError(
                    "Could not parse httpx JSONL at line " + str(line_number) + ": " + str(exc)
                ) from exc
            if not isinstance(record, dict):
                continue
            try:
                status_code = int(record.get("status_code") or 0)
            except (TypeError, ValueError):
                continue
            if status_code < 1:
                continue
            technologies = record.get("tech") or []
            if not isinstance(technologies, list):
                technologies = [technologies]
            results.append(
                {
                    "hostname": _hostname(record),
                    "status_code": status_code,
                    "title": str(record.get("title") or ""),
                    "technologies": sorted(str(item) for item in technologies),
                }
            )
    return sorted(results, key=lambda item: (item["status_code"], item["hostname"].casefold()))


def build_summary(domain: str, total_subdomains: int, results: list[dict[str, Any]]) -> dict[str, Any]:
    families = {family: 0 for family in ("2xx", "3xx", "4xx", "5xx")}
    grouped: dict[int, list[dict[str, Any]]] = {}
    for result in results:
        status_code = result["status_code"]
        grouped.setdefault(status_code, []).append(result)
        family = str(status_code // 100) + "xx"
        if family in families:
            families[family] += 1
    return {
        "domain": domain,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_subdomains": total_subdomains,
        "total_live": len(results),
        "status_families": families,
        "by_status": [
            {"status_code": status_code, "hosts": grouped[status_code]}
            for status_code in sorted(grouped)
        ],
    }


def _markdown_cell(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_text(summary: dict[str, Any]) -> str:
    families = summary["status_families"]
    lines = [
        "# Recon summary: " + summary["domain"],
        "",
        "- Generated: " + summary["generated_at"],
        "- Subdomains found: " + str(summary["total_subdomains"]),
        "- Live hosts: " + str(summary["total_live"]),
        "- Status families: " + ", ".join(f"{name}={families[name]}" for name in ("2xx", "3xx", "4xx", "5xx")),
        "",
    ]
    if not summary["by_status"]:
        lines.append("_No live hosts found._")
        return "\n".join(lines) + "\n"

    for group in summary["by_status"]:
        lines.extend(
            [
                "### HTTP " + str(group["status_code"]),
                "",
                "| Hostname | Status code | Title | Technologies |",
                "| --- | ---: | --- | --- |",
            ]
        )
        for host in group["hosts"]:
            lines.append(
                "| "
                + " | ".join(
                    (
                        _markdown_cell(host["hostname"]),
                        str(host["status_code"]),
                        _markdown_cell(host["title"]),
                        _markdown_cell(", ".join(host["technologies"])),
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_reports(
    domain: str,
    total_subdomains: int,
    live_hosts_path: Path,
    summary_text_path: Path,
    summary_json_path: Path,
) -> dict[str, Any]:
    results = load_results(live_hosts_path)
    summary = build_summary(domain, total_subdomains, results)
    summary_json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    summary_text_path.write_text(render_text(summary), encoding="utf-8")
    return summary


def _print_error(error: LivesubError, silent: bool) -> None:
    print("Error: " + str(error), file=sys.stderr)
    if isinstance(error, CommandError) and error.stderr and not silent:
        print(error.stderr, file=sys.stderr, end="" if error.stderr.endswith("\n") else "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if not DOMAIN_RE.fullmatch(args.domain):
        parser.error(f"{args.domain!r} does not look like a domain name")

    try:
        subfinder = require_subfinder(args.subfinder_bin)
        httpx = require_httpx(args.httpx_bin)
    except LivesubError as error:
        _print_error(error, args.silent)
        return 1

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.outdir or f"./reconchain_{args.domain}_{timestamp}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Error: could not create output directory {output_dir}: {exc}", file=sys.stderr)
        return 1

    subdomains_path = output_dir / "subdomains.txt"
    live_hosts_path = output_dir / "live_hosts.txt"
    summary_text_path = output_dir / "summary.txt"
    summary_json_path = output_dir / "summary.json"

    progress(args.silent, f"Enumerating subdomains for {args.domain}...")
    try:
        run_subfinder(subfinder, args.domain, args.t, subdomains_path)
        total_subdomains = count_nonempty_lines(subdomains_path)
        live_hosts_path.write_text("", encoding="utf-8")

        if total_subdomains:
            progress(args.silent, f"Probing {total_subdomains} subdomains with ProjectDiscovery httpx...")
            run_httpx(httpx, args.t, args.timeout, subdomains_path, live_hosts_path)
        else:
            progress(args.silent, "No subdomains found; skipping httpx.")

        progress(args.silent, "Building grouped text and JSON reports...")
        summary = write_reports(
            args.domain,
            total_subdomains,
            live_hosts_path,
            summary_text_path,
            summary_json_path,
        )
    except (LivesubError, OSError) as error:
        _print_error(error if isinstance(error, LivesubError) else LivesubError(str(error)), args.silent)
        return 1

    families = summary["status_families"]
    print(
        f"Summary: {summary['total_subdomains']} subdomains found, "
        f"{summary['total_live']} live | 2xx: {families['2xx']}, "
        f"3xx: {families['3xx']}, 4xx: {families['4xx']}, 5xx: {families['5xx']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
