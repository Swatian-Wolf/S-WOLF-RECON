import os
import re
import subprocess
from pathlib import Path
from shutil import which
from rich.console import Console
from rich.table import Table
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()
TOOLS = [
    "subfinder",
    "httpx",
    "nmap",
    "amass",
    "nuclei",
    "waybackurls",
    "gau",
    "ffuf",
    "katana",
    "dnsx",
    "assetfinder",
    "gitleaks",
    "trufflehog",
    "cloud_enum",
    "whatweb",
    "dig",
    "openssl",
    "sslscan",
    "theHarvester",
]
INSTALL_COMMANDS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nmap": "sudo apt-get install -y nmap",
    "amass": "go install -v github.com/owasp-amass/amass/v3/...@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "ffuf": "go install -v github.com/ffuf/ffuf@latest",
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "gitleaks": "go install -v github.com/zricethezav/gitleaks/v8@latest",
    "trufflehog": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b \"$HOME/.local/bin\"",
    "cloud_enum": "Automatic Go install currently unavailable; install manually if needed",
    "whatweb": "brew install whatweb  # or install via package manager",
    "dig": "sudo apt-get install -y dnsutils  # Debian/Ubuntu",
    "openssl": "sudo apt-get install -y openssl",
    "sslscan": "sudo apt-get install -y sslscan",
    "theHarvester": "go install -v github.com/laramies/theHarvester@latest",
}

def _resolve_tool_exists(tool: str, tool_paths: dict | None = None) -> bool:
    custom_path = None
    if tool_paths and tool in tool_paths:
        custom_path = tool_paths[tool]
        custom_file = Path(custom_path)
        if custom_file.exists() and custom_file.is_file() and custom_file.stat().st_mode & 0o111:
            return True
    search_target = custom_path or tool
    return bool(which(search_target))


def get_tool_status(tool_paths: dict | None = None):
    return {tool: _resolve_tool_exists(tool, tool_paths) for tool in TOOLS}


def _command_available(command: str) -> bool:
    return bool(which(command.split()[0]))


def _extract_progress_percentage(line: str) -> int | None:
    match = re.search(r"(\d{1,3})\s*%", line)
    if match:
        try:
            value = int(match.group(1))
            return min(max(value, 0), 100)
        except ValueError:
            return None
    return None


def install_tools(missing_tools: list[str], tool_paths: dict | None = None) -> tuple[list[str], list[str]]:
    installed = []
    failed = []
    total = len(missing_tools)
    for index, tool in enumerate(missing_tools, start=1):
        install_command = INSTALL_COMMANDS.get(tool)
        if not install_command:
            console.print(f"No automatic install command defined for {tool}.", style="bold yellow")
            failed.append(tool)
            continue

        if tool == "cloud_enum":
            console.print(
                "Automatic install for cloud_enum is currently unavailable because the upstream repository is not available."
                " Install it manually if you need it.",
                style="bold yellow",
            )
            failed.append(tool)
            continue

        console.print(f"\n[bold cyan]Installing {tool} ({index}/{total})[/bold cyan]")
        env = os.environ.copy()
        if install_command.startswith("go install") or "-b \"$HOME/.local/bin\"" in install_command:
            go_bin = str(Path.home() / ".local" / "bin")
            env["GOBIN"] = go_bin
            env["PATH"] = f"{go_bin}:{env.get('PATH', '')}"
            existing_godebug = env.get("GODEBUG", "").strip()
            env["GODEBUG"] = (
                f"{existing_godebug},netdns=go" if existing_godebug else "netdns=go"
            )
            os.environ["PATH"] = env["PATH"]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"{tool}", total=100)
            process = subprocess.Popen(
                install_command,
                shell=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                executable="/bin/bash",
            )
            if process.stdout is not None:
                for raw_line in process.stdout:
                    line = raw_line.rstrip()
                    if not line:
                        continue
                    console.print(f"[dim]{line}[/dim]")
                    percent = _extract_progress_percentage(line)
                    if percent is not None:
                        progress.update(task, completed=percent, description=f"{tool} {percent}%")
            process.wait()
            if process.returncode == 0:
                progress.update(task, completed=100, description=f"{tool} completed")
                console.print(f"Finished install command for {tool}.", style="green")
            else:
                console.print(
                    f"Installation command for {tool} failed with exit code {process.returncode}.",
                    style="bold red",
                )

        if _resolve_tool_exists(tool, tool_paths):
            installed.append(tool)
        else:
            failed.append(tool)

    return installed, failed


def print_startup_table(tool_paths: dict | None = None):
    status = get_tool_status(tool_paths)
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Tool Name", style="white")
    table.add_column("Status", style="white")
    for tool in TOOLS:
        if status[tool]:
            table.add_row(tool, "✅ Installed")
        else:
            table.add_row(tool, "❌ Missing")
    console.print(table)


def verify_tools(required_tools, tool_paths: dict | None = None):
    status = get_tool_status(tool_paths)
    missing = [tool for tool in required_tools if not status.get(tool)]
    if missing:
        for tool in missing:
            install_command = INSTALL_COMMANDS.get(tool, "Refer to the tool documentation for installation steps")
            console.print(
                f"Tool missing: {tool}. Install with: {install_command}",
                style="bold red",
            )
    return missing
