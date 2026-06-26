import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote_plus, urljoin, urlparse

from utils.display import print_result_table, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, write_to_file


OPEN_REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "dest",
    "destination",
    "redir",
    "goto",
    "continue",
]
EXTERNAL_TEST_URL = "https://example.com"
CSP_ISSUE_PATTERNS = [r"unsafe-inline", r"unsafe-eval", r"data:", r"http:"]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_root_url(target: str) -> str:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return f"{scheme}://{netloc.rstrip('/')}"


def _fetch_headers(url: str, timeout: int = 20) -> tuple[bool, int, dict[str, str], str]:
    request = urllib.request.Request(url, headers={"User-Agent": "SWOLF-RECON/1.0"})
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            return True, response.getcode(), dict(response.headers), ""
    except urllib.error.HTTPError as exc:
        return True, exc.code, dict(exc.headers), ""
    except urllib.error.URLError as exc:
        return False, 0, {}, str(exc.reason)
    except Exception as exc:
        return False, 0, {}, str(exc)


def _probe_open_redirects(root_url: str, timeout: int = 20) -> list[str]:
    findings = []
    for param in OPEN_REDIRECT_PARAMS:
        test_url = f"{root_url}/?{param}={quote_plus(EXTERNAL_TEST_URL)}"
        success, status, headers, error = _fetch_headers(test_url, timeout)
        if not success:
            findings.append(f"{test_url} -> request failed: {error}")
            continue
        location = headers.get("Location", "").strip()
        if status in range(300, 400) and location:
            findings.append(f"Possible redirect: {test_url} -> {location} ({status})")
        elif EXTERNAL_TEST_URL in location:
            findings.append(f"Possible open redirect: {test_url} -> {location} ({status})")
    return findings


def _evaluate_cors(headers: dict[str, str], root_url: str) -> list[str]:
    findings = []
    origin = headers.get("Access-Control-Allow-Origin")
    credentials = headers.get("Access-Control-Allow-Credentials")
    if origin:
        findings.append(f"Access-Control-Allow-Origin: {origin}")
        if origin == "*" and credentials:
            findings.append("Insecure CORS: wildcard origin with credentials allowed")
        elif origin != "*" and root_url not in origin:
            findings.append(f"CORS allows external origin: {origin}")
    else:
        findings.append("No Access-Control-Allow-Origin header present.")

    if credentials:
        findings.append(f"Access-Control-Allow-Credentials: {credentials}")
    return findings


def _evaluate_csp(headers: dict[str, str]) -> list[str]:
    findings = []
    csp = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only")
    if not csp:
        findings.append("No CSP header present.")
        return findings
    findings.append("CSP header found.")
    for pattern in CSP_ISSUE_PATTERNS:
        if re.search(pattern, csp, re.IGNORECASE):
            findings.append(f"CSP issue: {pattern} appears in policy")
    return findings


def run(target, session_dir, config=None):
    """Perform miscellaneous checks and save results to the session folder."""
    print_section(f"Misc Checks: {target}")
    filename = FILENAME_MAP["misc_checks"]
    session_path = Path(session_dir)
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 180) if isinstance(config, dict) else 180

    root_url = _build_root_url(target)
    report_lines = [f"=== Misc Checks for {target} ===", f"Root URL: {root_url}"]

    success, status, headers, error = _fetch_headers(root_url, timeout_seconds)
    if not success:
        message = f"Failed to fetch root URL: {error}"
        report_lines.append(message)
        print_warning(message)
        write_to_file(session_path, filename, "\n".join(report_lines), "Misc Checks", target)
        return

    report_lines.append(f"Root fetch HTTP status: {status}")
    report_lines.append("\n--- HTTP headers ---")
    for header, value in headers.items():
        report_lines.append(f"{header}: {value}")

    report_lines.append("\n--- CORS evaluation ---")
    cors_findings = _evaluate_cors(headers, root_url)
    report_lines.extend(cors_findings)

    report_lines.append("\n--- CSP evaluation ---")
    csp_findings = _evaluate_csp(headers)
    report_lines.extend(csp_findings)

    report_lines.append("\n--- Open redirect probes ---")
    redirect_findings = _probe_open_redirects(root_url, timeout_seconds)
    if redirect_findings:
        report_lines.extend(redirect_findings)
    else:
        report_lines.append("No open redirect behavior detected from common query parameters.")

    if cors_findings:
        rows = [(item,) for item in cors_findings]
        print_result_table(["CORS Findings"], rows)
    if csp_findings:
        rows = [(item,) for item in csp_findings]
        print_result_table(["CSP Findings"], rows)
    if redirect_findings:
        rows = [(item,) for item in redirect_findings[:20]]
        print_result_table(["Open Redirect Probe"], rows)

    write_to_file(session_path, filename, "\n".join(report_lines), "Misc Checks", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
