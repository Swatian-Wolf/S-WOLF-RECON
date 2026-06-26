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


def _parse_nmap_ports(output: str) -> list[tuple[str, str, str, str]]:
    ports = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Host:") and "Ports:" in line:
            parts = line.split("Ports:")[1].strip().split(",")
            for port_info in parts:
                port_info = port_info.strip()
                if not port_info:
                    continue
                fields = port_info.split("/")
                if len(fields) >= 7:
                    port = fields[0]
                    state = fields[1]
                    proto = fields[2]
                    service = fields[6]
                    ports.append((port, proto, state, service))
    return ports


def run(target, session_dir, config=None):
    """Perform port scanning on the target and save results to the session folder."""
    print_section(f"Port Scanning: {target}")
    filename = FILENAME_MAP["port_scan"]
    session_path = Path(session_dir)

    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    nmap_path = tool_paths.get("nmap", "nmap")
    flags = config.get("scan_defaults", {}).get("nmap_flags", "-sV -T4 --top-ports 1000")
    nmap_command = [nmap_path, *flags.split(), "-oG", "-", target]

    report_lines = ["=== nmap Output ==="]
    success, stdout, stderr = _run_command(nmap_command)
    if not success:
        print_warning(f"nmap failed: {stderr}")
        report_lines.append(f"nmap error: {stderr}")
    else:
        report_lines.append(stdout.strip())

    ports = _parse_nmap_ports(stdout if stdout else "")
    if ports:
        rows = [(port, proto, state, service) for port, proto, state, service in ports]
        print_result_table(["Port", "Proto", "State", "Service"], rows)
    else:
        if stdout.strip():
            print_warning("No open ports parsed from nmap output.")
        else:
            print_warning("No results found for nmap scan.")

    if not stdout.strip():
        report_lines.append("\nNo nmap output produced.")

    write_to_file(session_path, filename, "\n".join(report_lines), "Port Scanning", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
