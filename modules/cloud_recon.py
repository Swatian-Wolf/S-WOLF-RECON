import subprocess
from pathlib import Path
from shutil import which

from utils.display import print_section, print_success, print_error
from utils.file_manager import FILENAME_MAP, write_to_file


def run(target, session_dir, config=None):
    """Perform cloud reconnaissance and save results to the session folder."""
    print_section(f"Cloud Recon: {target}")
    filename = FILENAME_MAP["cloud_recon"]
    tool_name = "cloud_enum"
    tool_path = None

    if config and "tool_paths" in config:
        tool_path = config["tool_paths"].get(tool_name)

    if tool_path:
        tool_binary = Path(tool_path)
    else:
        tool_binary = Path(tool_name)

    if not (tool_binary.exists() or which(str(tool_binary))):
        error_msg = (
            f"Cloud enumeration tool not found: {tool_binary}. "
            "Set the path in config.yaml under tool_paths.cloud_enum."
        )
        print_error(error_msg)
        write_to_file(
            session_dir,
            filename,
            f"ERROR: {error_msg}\n",
            "Cloud Recon",
            target,
        )
        return

    command = [str(tool_binary), "-d", target, "-o", str(session_dir / "cloud_enum_raw.txt")]
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 300) if config else 300

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if completed.returncode != 0:
            result_content = (
                f"Cloud enumeration returned non-zero exit status {completed.returncode}.\n"
                f"stderr:\n{completed.stderr.strip()}\n"
            )
            print_error("Cloud reconnaissance failed. See session output for details.")
        else:
            result_content = completed.stdout.strip() or "No cloud reconnaissance results were returned."
            print_success("Cloud reconnaissance completed successfully.")

        raw_output_path = session_dir / "cloud_enum_raw.txt"
        if raw_output_path.exists():
            raw_text = raw_output_path.read_text(encoding="utf-8", errors="ignore")
            result_content += f"\n\n--- Raw tool output from {raw_output_path.name} ---\n{raw_text.strip()}\n"

    except subprocess.TimeoutExpired as exc:
        result_content = (
            f"Cloud enumeration timed out after {timeout_seconds} seconds.\n"
            f"Partial output:\n{exc.stdout or ''}\n"
            f"Partial stderr:\n{exc.stderr or ''}\n"
        )
        print_error("Cloud reconnaissance timed out.")

    write_to_file(session_dir, filename, result_content, "Cloud Recon", target)
    print_success(f"Module complete. Results saved to: {session_dir / filename}")
