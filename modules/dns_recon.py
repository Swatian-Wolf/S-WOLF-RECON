import re
import subprocess
from pathlib import Path

from utils.display import print_error, print_section, print_success, print_warning, print_result_table
from utils.file_manager import FILENAME_MAP, write_to_file

DNS_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"}


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


def _parse_dnsx_output(output: str) -> list[tuple[str, str]]:
    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        record_type = parts[3].upper()
        if record_type not in DNS_TYPES:
            continue
        value = " ".join(parts[4:])
        records.append((record_type, value))
    return records


def _parse_ns_servers(output: str) -> list[str]:
    servers = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 5 and parts[3].upper() == "NS":
            servers.append(parts[4].rstrip("."))
    return sorted(set(servers))


def _attempt_zone_transfer(target: str, ns_server: str) -> tuple[bool, str]:
    command = ["dig", "AXFR", target, f"@{ns_server}"]
    success, stdout, stderr = _run_command(command)
    if not success:
        return False, stderr
    zone_lines = [line for line in stdout.splitlines() if line.strip() and not line.startswith(";")]
    if not zone_lines:
        return False, stdout or "No zone transfer output."
    return True, "\n".join(zone_lines)


def run(target: str, session_dir: str, config=None):
    """Runs DNS reconnaissance on the target and saves results to dns_records.txt."""
    print_section(f"DNS Recon: {target}")
    session_path = Path(session_dir)
    filename = FILENAME_MAP["dns_recon"]
    output_lines = []
    parsed_records = []
    ns_servers = []
    zone_transfer_alerts = []

    output_lines.append("=== dnsx Output ===")
    dnsx_command = [
        "dnsx",
        "-a",
        "-aaaa",
        "-mx",
        "-txt",
        "-ns",
        "-cname",
        "-soa",
        "-silent",
        target,
    ]
    success, stdout, stderr = _run_command(dnsx_command)
    if not success:
        print_warning(f"dnsx did not complete successfully: {stderr}")
        output_lines.append(f"dnsx error: {stderr}")
    else:
        output_lines.append(stdout.strip())
        parsed_records = _parse_dnsx_output(stdout)
        ns_servers = _parse_ns_servers(stdout)

    if parsed_records:
        table_rows = [(record_type, value) for record_type, value in parsed_records]
        print_result_table(["Record Type", "Value"], table_rows)
    else:
        print_warning("No DNS records were parsed from dnsx output.")

    if not ns_servers:
        ns_command = ["dig", target, "NS", "+short"]
        success, stdout, stderr = _run_command(ns_command)
        if success:
            ns_servers = [line.strip().rstrip(".") for line in stdout.splitlines() if line.strip()]
        else:
            print_warning(f"Unable to fetch NS records with dig: {stderr}")

    if ns_servers:
        output_lines.append("\n=== NS Servers ===")
        for ns in ns_servers:
            output_lines.append(ns)
    else:
        output_lines.append("\n=== NS Servers ===")
        output_lines.append("No NS servers discovered.")

    output_lines.append("\n=== Zone Transfer Attempts ===")
    for ns_server in ns_servers:
        success, transfer_output = _attempt_zone_transfer(target, ns_server)
        output_lines.append(f"Zone transfer attempt against {ns_server}:")
        if success:
            zone_transfer_alerts.append((ns_server, transfer_output))
            output_lines.append(transfer_output)
        else:
            output_lines.append(f"Failed or denied: {transfer_output}")

    if zone_transfer_alerts:
        print_warning("Zone transfer succeeded for at least one NS server. This is a critical finding.")
        for ns_server, transfer_output in zone_transfer_alerts:
            print_error(f"Zone transfer succeeded on {ns_server}")
            output_lines.append(f"\n=== Zone Transfer Successful on {ns_server} ===")
            output_lines.append(transfer_output)

    write_to_file(session_path, filename, "\n".join(output_lines), "DNS Recon", target)
    print_success(f"DNS recon results saved to {session_path / filename}")
