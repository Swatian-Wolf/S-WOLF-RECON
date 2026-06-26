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


def _extract_emails(output: str) -> list[str]:
    return sorted({match.group(0) for match in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", output)})


def run(target, session_dir, config=None):
    """Perform email enumeration and save results to the session folder."""
    print_section(f"Email Enumeration: {target}")
    filename = FILENAME_MAP["email_enum"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    theharvester_path = tool_paths.get("theHarvester", "theHarvester")
    timeout = config.get("scan_defaults", {}).get("timeout_seconds", 120)

    command = [
        theharvester_path,
        "-d",
        target,
        "-b",
        "all",
    ]
    report_lines = ["=== theHarvester Output ==="]
    success, stdout, stderr = _run_command(command, timeout=timeout)
    if not success:
        print_warning(f"theHarvester failed: {stderr}")
        report_lines.append(f"theHarvester error: {stderr}")
    else:
        report_lines.append(stdout.strip())

    emails = _extract_emails(stdout if stdout else "")
    if emails:
        print_result_table(["Email"], [(email,) for email in emails])
    else:
        if stdout.strip():
            print_warning("No email addresses parsed from theHarvester output.")
        else:
            print_warning("No results found for email enumeration.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Email Enumeration", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
