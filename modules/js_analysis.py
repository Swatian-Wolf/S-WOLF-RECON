import re
import subprocess
import urllib.request
from pathlib import Path
from shutil import which
from urllib.parse import urljoin, urlparse

from utils.display import print_error, print_result_table, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, write_to_file


JS_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+\.js|/[^\s'\"]+\.js", re.IGNORECASE)
SENSITIVE_PATTERNS = [
    r"api[_-]?key",
    r"secret",
    r"token",
    r"auth",
    r"pass(word)?",
    r"client[_-]?id",
    r"client[_-]?secret",
    r"bearer",
    r"jwt",
]


def _run_command(command: list[str], timeout: int = 180) -> tuple[bool, str, str]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if process.returncode != 0:
            return False, process.stdout or "", process.stderr or f"Command exited with {process.returncode}"
        return True, process.stdout or "", process.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return False, exc.stdout or "", exc.stderr or f"Command timed out after {timeout} seconds"
    except FileNotFoundError as exc:
        return False, "", str(exc)


def _build_root_url(target: str) -> str:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return f"{scheme}://{netloc.rstrip('/')}"


def _normalize_js_urls(raw_text: str, root_url: str) -> list[str]:
    urls = set()
    for match in JS_PATTERN.finditer(raw_text):
        candidate = match.group(0)
        if candidate.startswith("/"):
            urls.add(urljoin(root_url, candidate))
        else:
            urls.add(candidate)
    return sorted(urls)


def _find_sensitive_strings(content: str) -> list[str]:
    findings = set()
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.add(pattern)
    return sorted(findings)


def _fetch_js_file(url: str, timeout: int = 15) -> tuple[str, str]:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "SWOLF-RECON/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore"), ""
    except Exception as exc:
        return "", str(exc)


def run(target, session_dir, config=None):
    """Perform JavaScript analysis and save results to the session folder."""
    print_section(f"JavaScript Analysis: {target}")
    filename = FILENAME_MAP["js_analysis"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 180) if isinstance(config, dict) else 180

    katana_path = tool_paths.get("katana", "katana")
    if not (Path(katana_path).exists() or which(katana_path)):
        missing_tool = f"katana binary not found: {katana_path}. Set tool_paths.katana in config.yaml or install katana."
        print_error(missing_tool)
        write_to_file(session_path, filename, missing_tool, "JavaScript Analysis", target)
        return

    root_url = _build_root_url(target)
    raw_output_file = session_path / "js_analysis_raw.txt"
    katana_command = [katana_path, "-u", root_url, "-d", "2", "-o", str(raw_output_file)]
    print_section("Running katana crawl for JavaScript discovery...")

    success, stdout, stderr = _run_command(katana_command, timeout=timeout_seconds)
    report_lines = [f"=== JavaScript Analysis for {target} ===", f"Root URL: {root_url}"]

    if not success:
        report_lines.append(f"katana failed: {stderr.strip()}")
        print_warning(f"katana scan failed: {stderr.strip()}")
    else:
        report_lines.append("katana completed successfully.")

    raw_text = ""
    if raw_output_file.exists():
        raw_text = raw_output_file.read_text(encoding="utf-8", errors="ignore")
        report_lines.append("\n--- katana raw output ---")
        report_lines.append(raw_text.strip())

    js_urls = _normalize_js_urls(raw_text, root_url)
    if js_urls:
        report_lines.append("\n--- JavaScript files discovered ---")
        for url in js_urls:
            report_lines.append(url)
    else:
        report_lines.append("No JavaScript files discovered from katana output.")

    findings = []
    fetch_results = []
    for js_url in js_urls[:20]:
        content, error = _fetch_js_file(js_url, timeout=timeout_seconds)
        if error:
            fetch_results.append((js_url, "fetch_failed", error))
            continue
        patterns = _find_sensitive_strings(content)
        fetch_results.append((js_url, "fetched", ", ".join(patterns) if patterns else "no sensitive patterns"))
        if patterns:
            findings.append(f"{js_url}: {', '.join(patterns)}")

    if fetch_results:
        report_lines.append("\n--- Fetched JS file summary ---")
        for url, status, info in fetch_results:
            report_lines.append(f"{url} | {status} | {info}")

    if findings:
        report_lines.append("\n--- Sensitive JS findings ---")
        report_lines.extend(findings)
        print_result_table(["JS File", "Findings"], [(url, info) for url, status, info in fetch_results if status == "fetched" and info != "no sensitive patterns"])  # type: ignore[arg-type]
    else:
        report_lines.append("No obvious sensitive strings found in discovered JS files.")
        if js_urls:
            print_warning("No obvious sensitive strings found in JS files, but review output for file list.")

    write_to_file(session_path, filename, "\n".join(report_lines), "JavaScript Analysis", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
