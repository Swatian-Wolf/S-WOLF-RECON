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


def _parse_ffuf_output(output: str) -> list[tuple[str, str, str]]:
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # ffuf normal output lines are often: /admin               [Status: 200, Size: 123, Words: 10]
        match = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),", line)
        if match:
            results.append((match.group(1), match.group(2), match.group(3)))
    return results


def run(target, session_dir, config=None):
    """Perform content discovery and save results to the session folder."""
    import re

    print_section(f"Content Discovery: {target}")
    filename = FILENAME_MAP["content_discovery"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    ffuf_path = tool_paths.get("ffuf", "ffuf")
    wordlist = config.get("scan_defaults", {}).get("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")
    threads = str(config.get("scan_defaults", {}).get("ffuf_threads", 50))
    url = target if target.startswith("http") else f"http://{target}"

    report_lines = ["=== ffuf Output ==="]
    if not Path(wordlist).exists():
        print_warning(f"Configured ffuf wordlist not found: {wordlist}")
        report_lines.append(f"ffuf wordlist not found: {wordlist}")
        write_to_file(session_path, filename, "\n".join(report_lines), "Content Discovery", target)
        print_success(f"Module complete. Results saved to: {session_path / filename}")
        return

    ffuf_command = [
        ffuf_path,
        "-u",
        f"{url}/FUZZ",
        "-w",
        wordlist,
        "-t",
        threads,
        "-mc",
        "200,301,302,403,500",
        "-s",
    ]
    success, stdout, stderr = _run_command(ffuf_command)
    if not success:
        print_warning(f"ffuf failed: {stderr}")
        report_lines.append(f"ffuf error: {stderr}")
    else:
        report_lines.append(stdout.strip())

    results = _parse_ffuf_output(stdout if stdout else "")
    if results:
        print_result_table(["Path", "Size", "Status"], results)
    else:
        if stdout.strip():
            print_warning("No content discovery results parsed from ffuf output.")
        else:
            print_warning("No results found for ffuf scan.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Content Discovery", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
