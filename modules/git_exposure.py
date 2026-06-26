import subprocess
import urllib.request
from pathlib import Path
from shutil import which
from urllib.parse import urljoin, urlparse

from utils.display import print_error, print_result_table, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, write_to_file


GIT_PROBE_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index"]


def _build_root_url(target: str) -> str:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    scheme = parsed.scheme or "https"
    host = parsed.netloc or parsed.path
    return f"{scheme}://{host.rstrip('/')}"


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


def _resolve_tool(tool: str, tool_paths: dict[str, str]) -> str:
    return tool_paths.get(tool, tool)


def _probe_git_paths(root_url: str, timeout: int = 15) -> list[str]:
    findings = []
    for path in GIT_PROBE_PATHS:
        url = urljoin(root_url, path)
        request = urllib.request.Request(url, headers={"User-Agent": "SWOLF-RECON/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read(1024).decode("utf-8", errors="ignore").strip()
                findings.append(f"Accessible: {url} | Status: {response.status} | Snippet: {content}")
        except urllib.error.HTTPError as http_err:
            findings.append(f"{url} | HTTP {http_err.code}")
        except urllib.error.URLError as url_err:
            findings.append(f"{url} | unreachable ({url_err.reason})")
        except Exception as exc:
            findings.append(f"{url} | error ({exc})")
    return findings


def _looks_like_git_repo(target: str) -> bool:
    lower = target.lower()
    return lower.endswith(".git") or any(host in lower for host in ["github.com", "gitlab.com", "bitbucket.org"])


def _run_gitleaks(source: str, gitleaks_path: str, timeout: int) -> tuple[bool, str, str]:
    command = [gitleaks_path, "detect", "--source", source, "--no-git", "--report-format", "text"]
    return _run_command(command, timeout)


def _run_trufflehog(source: str, trufflehog_path: str, timeout: int) -> tuple[bool, str, str]:
    if _looks_like_git_repo(source):
        command = [trufflehog_path, "git", source, "--json"]
    else:
        command = [trufflehog_path, "filesystem", source, "--json"]
    return _run_command(command, timeout)


def run(target, session_dir, config=None):
    """Perform git exposure checks and save results to the session folder."""
    print_section(f"Git Exposure: {target}")
    filename = FILENAME_MAP["git_exposure"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 180) if isinstance(config, dict) else 180

    gitleaks_path = _resolve_tool("gitleaks", tool_paths)
    trufflehog_path = _resolve_tool("trufflehog", tool_paths)

    report_lines = [f"=== Git Exposure for {target} ==="]
    root_url = _build_root_url(target)
    report_lines.append(f"Root URL: {root_url}")

    report_lines.append("\n--- .git exposure probe ---")
    git_probe_results = _probe_git_paths(root_url, timeout=timeout_seconds)
    for line in git_probe_results:
        report_lines.append(line)

    if Path(target).exists():
        report_lines.append("\n--- Local path analysis ---")
        source = str(Path(target).resolve())
    elif _looks_like_git_repo(target):
        report_lines.append("\n--- Remote git repository suspected ---")
        source = target
    else:
        report_lines.append("\n--- Remote path is not clearly a git repo. Secret scanning will be skipped unless target is a repo URL or local path.")
        source = None

    if source:
        if Path(gitleaks_path).exists() or which(gitleaks_path):
            success, stdout, stderr = _run_gitleaks(source, gitleaks_path, timeout_seconds)
            report_lines.append("\n--- gitleaks scan ---")
            if success:
                report_lines.append(stdout.strip() or "gitleaks completed with no findings.")
            else:
                report_lines.append(f"gitleaks error: {stderr.strip()}")
        else:
            report_lines.append(f"gitleaks not found: {gitleaks_path}")
            print_warning("gitleaks not available; skipping secret scan.")

        if Path(trufflehog_path).exists() or which(trufflehog_path):
            success, stdout, stderr = _run_trufflehog(source, trufflehog_path, timeout_seconds)
            report_lines.append("\n--- trufflehog scan ---")
            if success:
                report_lines.append(stdout.strip() or "trufflehog completed with no findings.")
            else:
                report_lines.append(f"trufflehog error: {stderr.strip()}")
        else:
            report_lines.append(f"trufflehog not found: {trufflehog_path}")
            print_warning("trufflehog not available; skipping secret scan.")
    else:
        report_lines.append("No source provided for gitleaks/trufflehog scanning.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Git Exposure", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
