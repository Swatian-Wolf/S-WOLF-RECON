import os
import subprocess
from pathlib import Path
from shutil import which
from rich.console import Console
from rich.table import Table

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
    "trufflehog": "go install -v github.com/trufflesecurity/trufflehog/v3@latest",
    "cloud_enum": "go install -v github.com/projectdiscovery/cloud_enum/cmd/cloud_enum@latest",
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


def install_tools(missing_tools: list[str], tool_paths: dict | None = None) -> tuple[list[str], list[str]]:
    installed = []
    failed = []
    for tool in missing_tools:
        install_command = INSTALL_COMMANDS.get(tool)
        if not install_command:
            console.print(f"No automatic install command defined for {tool}.", style="bold yellow")
            failed.append(tool)
            continue

        console.print(f"Installing {tool}...", style="bold yellow")
        env = os.environ.copy()
        if install_command.startswith("go install"):
            env["GOBIN"] = str(Path.home() / ".local" / "bin")
            env["PATH"] = f"{env['GOBIN']}:{env.get('PATH', '')}"
        result = subprocess.run(install_command, shell=True, env=env, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"Finished install command for {tool}.", style="green")
        else:
            console.print(
                f"Installation command for {tool} failed with exit code {result.returncode}.\n"
                f"{result.stderr or result.stdout}",
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
