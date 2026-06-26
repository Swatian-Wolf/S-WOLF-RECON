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


def _parse_urls(output: str) -> set[str]:
    urls = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        urls.add(line)
    return urls


def run(target, session_dir, config=None):
    """Collect URLs using katana, gau, and waybackurls and save results."""
    print_section(f"URL Collection: {target}")
    filename = FILENAME_MAP["url_collection"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}

    katana_path = tool_paths.get("katana", "katana")
    gau_path = tool_paths.get("gau", "gau")
    wayback_path = tool_paths.get("waybackurls", "waybackurls")
    normalized_target = _normalize_url(target)

    report_lines = ["=== katana Output ==="]
    all_urls = set()

    katana_command = [katana_path, "-u", normalized_target, "-silent"]
    success, stdout, stderr = _run_command(katana_command)
    if success:
        katana_urls = _parse_urls(stdout)
        all_urls.update(katana_urls)
        report_lines.append(stdout.strip())
    else:
        print_warning(f"katana failed: {stderr}")
        report_lines.append(f"katana error: {stderr}")

    report_lines.append("\n=== gau Output ===")
    gau_command = [gau_path, target]
    success, stdout, stderr = _run_command(gau_command)
    if success:
        gau_urls = _parse_urls(stdout)
        all_urls.update(gau_urls)
        report_lines.append(stdout.strip())
    else:
        print_warning(f"gau failed: {stderr}")
        report_lines.append(f"gau error: {stderr}")

    report_lines.append("\n=== waybackurls Output ===")
    wayback_command = [wayback_path, target]
    success, stdout, stderr = _run_command(wayback_command)
    if success:
        wayback_urls = _parse_urls(stdout)
        all_urls.update(wayback_urls)
        report_lines.append(stdout.strip())
    else:
        print_warning(f"waybackurls failed: {stderr}")
        report_lines.append(f"waybackurls error: {stderr}")

    if all_urls:
        rows = [(url,) for url in sorted(all_urls)]
        print_result_table(["URL"], rows)
    else:
        print_warning("No URLs discovered from katana, gau, or waybackurls.")

    write_to_file(session_path, filename, "\n".join(report_lines), "URL Collection", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
