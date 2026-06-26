import subprocess
from pathlib import Path
from shutil import which
from urllib.parse import urlparse

from utils.display import print_error, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, write_to_file


def _normalize_target(target: str) -> tuple[str, int, str]:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    hostname = parsed.hostname or target
    port = parsed.port or 443
    return hostname, port, hostname


def _run_command(command: list[str], timeout: int = 120) -> tuple[bool, str, str]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input="",
        )
        if process.returncode != 0:
            return False, process.stdout or "", process.stderr or f"Command exited with {process.returncode}"
        return True, process.stdout or "", process.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return False, exc.stdout or "", exc.stderr or f"Command timed out after {timeout} seconds"
    except FileNotFoundError as exc:
        return False, "", str(exc)


def _resolve_tool(tool: str, tool_paths: dict[str, str]) -> str:
    custom_path = tool_paths.get(tool)
    if custom_path:
        return custom_path
    return tool


def run(target, session_dir, config=None):
    """Perform SSL/TLS analysis on the target and save results to the session folder."""
    print_section(f"SSL/TLS Analysis: {target}")
    filename = FILENAME_MAP["ssl_analysis"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 180) if isinstance(config, dict) else 180

    host, port, sni = _normalize_target(target)
    openssl_path = _resolve_tool("openssl", tool_paths)
    sslscan_path = _resolve_tool("sslscan", tool_paths)

    report_lines = [f"=== SSL/TLS Analysis for {host}:{port} ==="]

    if not (Path(openssl_path).exists() or which(openssl_path)):
        report_lines.append("openssl binary not found. Skipping certificate extraction.")
        print_warning("openssl not available; skipping certificate extraction.")
    else:
        report_lines.append("\n--- openssl s_client / certificate chain ---")
        openssl_command = [openssl_path, "s_client", "-connect", f"{host}:{port}", "-servername", sni, "-showcerts"]
        success, stdout, stderr = _run_command(openssl_command, timeout=timeout_seconds)
        if not success:
            print_warning(f"openssl scan failed: {stderr.strip()}")
            report_lines.append(f"openssl error: {stderr.strip()}")
        else:
            report_lines.append(stdout.strip())

    if not (Path(sslscan_path).exists() or which(sslscan_path)):
        report_lines.append("sslscan binary not found. Skipping cipher and protocol review.")
        print_warning("sslscan not available; skipping cipher and protocol review.")
    else:
        report_lines.append("\n--- sslscan results ---")
        sslscan_command = [sslscan_path, "--no-color", "--no-failed", f"{host}:{port}"]
        success, stdout, stderr = _run_command(sslscan_command, timeout=timeout_seconds)
        if not success:
            print_warning(f"sslscan failed: {stderr.strip()}")
            report_lines.append(f"sslscan error: {stderr.strip()}")
        else:
            report_lines.append(stdout.strip())

    if len(report_lines) == 1:
        report_lines.append("No SSL/TLS analysis could be performed. Ensure openssl or sslscan is installed.")

    write_to_file(session_path, filename, "\n".join(report_lines), "SSL/TLS Analysis", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
