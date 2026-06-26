import subprocess
from pathlib import Path

from rich.table import Table

from utils.display import print_error, print_section, print_success, print_warning, print_result_table
from utils.file_manager import FILENAME_MAP, write_to_file


def _run_command(command: list[str], timeout: int = 60) -> tuple[bool, str, str]:
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


def _parse_subdomains(output: str) -> list[str]:
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def run(target, session_dir, config=None):
    """Perform subdomain enumeration and save results to the session folder."""
    print_section(f"Subdomain Enumeration: {target}")
    filename = FILENAME_MAP["subdomain_enum"]
    session_path = Path(session_dir)

    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    subdomains = []
    report_lines = ["=== subfinder Output ==="]

    subfinder_cmd = [tool_paths.get("subfinder", "subfinder"), "-d", target, "-silent"]
    success, stdout, stderr = _run_command(subfinder_cmd)
    if success:
        subdomains.extend(_parse_subdomains(stdout))
        report_lines.append(stdout.strip())
    else:
        print_warning(f"subfinder failed: {stderr}")
        report_lines.append(f"subfinder error: {stderr}")

    amass_path = tool_paths.get("amass", "amass")
    amass_cmd = [amass_path, "enum", "-passive", "-d", target]
    success, stdout, stderr = _run_command(amass_cmd)
    if success:
        parsed = _parse_subdomains(stdout)
        if parsed:
            subdomains.extend(parsed)
            report_lines.append("\n=== amass Output ===")
            report_lines.append(stdout.strip())
    else:
        print_warning(f"amass failed or was skipped: {stderr}")
        report_lines.append(f"amass error: {stderr}")

    unique_subdomains = sorted(set(subdomains))
    if unique_subdomains:
        rows = [(subdomain,) for subdomain in unique_subdomains]
        print_result_table(["Subdomain"], rows)
    else:
        print_warning("No results found for subdomain enumeration.")

    if not unique_subdomains:
        report_lines.append("\nNo subdomains discovered.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Subdomain Enumeration", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
