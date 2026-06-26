import json
import re
import subprocess
from pathlib import Path

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


def _parse_httpx_output(output: str) -> dict:
    result = {
        "Status": "",
        "Server": "",
        "Title": "",
        "Content-Type": "",
        "Content-Length": "",
        "Location": "",
    }
    status_match = re.search(r"\[(\d{3})\]", output)
    if status_match:
        result["Status"] = status_match.group(1)
    server_match = re.search(r"Server:\s*([^\s\[]+)", output)
    if server_match:
        result["Server"] = server_match.group(1)
    title_match = re.search(r"Title:\s*(.*?)($|\s{2,}|\n)", output)
    if title_match:
        result["Title"] = title_match.group(1).strip()
    content_type_match = re.search(r"Content-Type:\s*([^\s\[]]+)", output)
    if content_type_match:
        result["Content-Type"] = content_type_match.group(1)
    content_length_match = re.search(r"Content-Length:\s*([^\s\[]]+)", output)
    if content_length_match:
        result["Content-Length"] = content_length_match.group(1)
    location_match = re.search(r"Location:\s*(.*?)($|\s{2,}|\n)", output)
    if location_match:
        result["Location"] = location_match.group(1).strip()
    return result


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

    httpx_path = tool_paths.get("httpx", "httpx")
    whatweb_path = tool_paths.get("whatweb", "whatweb")
    report_lines = ["=== httpx Output ==="]
    httpx_command = [
        httpx_path,
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-server",
        "-title",
        "-content-type",
        "-content-length",
        "-location",
        url,
    ]
    success, stdout, stderr = _run_command(httpx_command)
    if not success:
        print_warning(f"httpx failed: {stderr}")
        report_lines.append(f"httpx error: {stderr}")
    else:
        report_lines.append(stdout.strip())

    fingerprint = _parse_httpx_output(stdout if stdout else "")
    rows = [(key, value or "-") for key, value in fingerprint.items()]
    if any(value for value in fingerprint.values()):
        print_result_table(["Field", "Value"], rows)
    else:
        print_warning("No HTTP fingerprint details parsed from httpx output.")

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
