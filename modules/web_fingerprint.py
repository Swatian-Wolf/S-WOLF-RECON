import re
import subprocess
from pathlib import Path

import requests

from utils.display import print_error, print_section, print_success, print_warning, print_result_table
from utils.file_manager import FILENAME_MAP, write_to_file


def _run_command(command: list[str], timeout: int = 120) -> tuple[bool, str, str]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if process.returncode != 0:
            return False, process.stdout, process.stderr or f"Command exited with {process.returncode}"
        return True, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout} seconds: {' '.join(command)}"
    except FileNotFoundError as exc:
        return False, "", str(exc)


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return match.group(1).strip() if match else ""


def _fetch_http_fingerprint(url: str) -> tuple[dict, list[str]]:
    result = {
        "Status": "",
        "Server": "",
        "Title": "",
        "Content-Type": "",
        "Content-Length": "",
        "Location": "",
    }
    report_lines = [f"URL: {url}"]
    try:
        response = requests.get(url, allow_redirects=True, timeout=15)
        result["Status"] = str(response.status_code)
        result["Server"] = response.headers.get("Server", "")
        result["Content-Type"] = response.headers.get("Content-Type", "")
        result["Content-Length"] = response.headers.get("Content-Length", "")
        result["Location"] = response.headers.get("Location", "")
        result["Title"] = _extract_title(response.text)

        report_lines.append(f"Status: {result['Status']}")
        report_lines.append(f"Server: {result['Server']}")
        report_lines.append(f"Title: {result['Title']}")
        report_lines.append(f"Content-Type: {result['Content-Type']}")
        report_lines.append(f"Content-Length: {result['Content-Length']}")
        if result["Location"]:
            report_lines.append(f"Location: {result['Location']}")
    except requests.RequestException as exc:
        report_lines.append(f"HTTP request failed: {exc}")
    return result, report_lines


def _parse_whatweb_output(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return ""
    techs = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 2:
            techs.append(parts[1].strip())
        else:
            pieces = line.split(" ", 2)
            if len(pieces) == 3:
                techs.append(pieces[2].strip())
    return ", ".join(techs)


def run(target, session_dir, config=None):
    """Perform web fingerprinting and save results to the session folder."""
    print_section(f"Web Fingerprinting: {target}")
    filename = FILENAME_MAP["web_fingerprint"]
    session_path = Path(session_dir)
    url = _normalize_url(target)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}

    whatweb_path = tool_paths.get("whatweb", "whatweb")
    report_lines = ["=== HTTP Request Output ==="]
    fingerprint, http_lines = _fetch_http_fingerprint(url)
    report_lines.extend(http_lines)

    rows = [(key, value or "-") for key, value in fingerprint.items()]
    if any(value for value in fingerprint.values()):
        print_result_table(["Field", "Value"], rows)
    else:
        print_warning("No HTTP fingerprint details parsed from HTTP request output.")

    report_lines.append("\n=== whatweb Output ===")
    whatweb_command = [whatweb_path, "--color=never", url]
    success, stdout, stderr = _run_command(whatweb_command)
    if not success:
        print_warning(f"whatweb failed: {stderr}")
        report_lines.append(f"whatweb error: {stderr}")
        techs = ""
    else:
        report_lines.append(stdout.strip())
        techs = _parse_whatweb_output(stdout)

    if techs:
        print_result_table(["Fingerprint", "Value"], [("WhatWeb Tech Stack", techs)])
    else:
        print_warning("No tech fingerprint data parsed from whatweb output.")

    if not stdout.strip():
        report_lines.append("\nNo whatweb output produced.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Web Fingerprinting", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
