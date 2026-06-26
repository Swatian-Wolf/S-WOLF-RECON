from pathlib import Path
import time
import yaml

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from modules import api_recon, cloud_recon, content_discovery, dns_recon, email_enum, git_exposure, js_analysis, misc_checks, port_scan, ssl_analysis, subdomain_enum, url_collection, web_fingerprint
from utils.banner import print_banner
from utils.display import print_error, print_info, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, create_session_folder, show_results_map
from utils.tool_checker import print_startup_table, verify_tools
from utils.validator import validate_file_of_targets, validate_menu_choice, validate_target

console = Console()

DEFAULT_CONFIG = {
    "tool_paths": {
        "nmap": "nmap",
        "subfinder": "subfinder",
        "httpx": "httpx",
        "amass": "amass",
        "nuclei": "nuclei",
        "waybackurls": "waybackurls",
        "gau": "gau",
        "ffuf": "ffuf",
        "katana": "katana",
        "dnsx": "dnsx",
        "assetfinder": "assetfinder",
        "gitleaks": "gitleaks",
        "trufflehog": "trufflehog",
        "cloud_enum": "cloud_enum",
        "whatweb": "whatweb",
        "dig": "dig",
        "openssl": "openssl",
        "sslscan": "sslscan",
        "theHarvester": "theHarvester",
    },
    "scan_defaults": {
        "nmap_flags": "-sV -T4 --top-ports 1000",
        "ffuf_wordlist": "/usr/share/wordlists/dirb/common.txt",
        "ffuf_threads": 50,
        "timeout_seconds": 120,
    },
    "output": {
        "results_dir": "Results",
        "verbose": True,
    },
    "first_run": True,
}


def get_project_root() -> Path:
    return Path(__file__).resolve().parent


def get_config_path() -> Path:
    return get_project_root() / "config.yaml"


def load_config() -> dict:
    config_path = get_config_path()
    if not config_path.exists():
        config_path.write_text(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False), encoding="utf-8")
        return DEFAULT_CONFIG.copy()
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print_error(f"Unable to load config.yaml: {exc}")
        raise
    config = {
        "tool_paths": {**DEFAULT_CONFIG["tool_paths"], **raw.get("tool_paths", {})},
        "scan_defaults": {**DEFAULT_CONFIG["scan_defaults"], **raw.get("scan_defaults", {})},
        "output": {**DEFAULT_CONFIG["output"], **raw.get("output", {})},
        "first_run": raw.get("first_run", DEFAULT_CONFIG["first_run"]),
    }
    return config


def save_config(config: dict) -> None:
    config_path = get_config_path()
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def apply_first_run(config: dict) -> None:
    if config.get("first_run", True):
        panel = Panel(
            Text(
                "Welcome to SWATIAN-WOLF RECON. This tool wraps reconnaissance utilities and saves structured scan results for easy review.",
                style="white",
            ),
            title="Welcome to SWATIAN-WOLF RECON",
            border_style="green",
        )
        console.print(panel)
        config["first_run"] = False
        save_config(config)


def check_ffuf_wordlist(config: dict) -> None:
    wordlist_path = Path(config.get("scan_defaults", {}).get("ffuf_wordlist", ""))
    if not wordlist_path.exists():
        print_warning(
            f"Configured ffuf wordlist not found: {wordlist_path}. "
            "Update config.yaml or choose a different wordlist path, such as /usr/share/wordlists/dirb/common.txt."
        )


def get_results_dir(config: dict) -> str:
    return config.get("output", {}).get("results_dir", "Results")


MODULES = [
    {
        "number": 1,
        "name": "DNS Recon",
        "description": "DNS records, zone transfer, history",
        "tools": ["dnsx", "dig"],
        "module": dns_recon,
        "key": "dns_recon",
    },
    {
        "number": 2,
        "name": "Subdomain Enumeration",
        "description": "Passive + active subdomain discovery",
        "tools": ["subfinder", "amass"],
        "module": subdomain_enum,
        "key": "subdomain_enum",
    },
    {
        "number": 3,
        "name": "Port Scanning",
        "description": "TCP/UDP port scan + service detect",
        "tools": ["nmap"],
        "module": port_scan,
        "key": "port_scan",
    },
    {
        "number": 4,
        "name": "Web Fingerprinting",
        "description": "CMS, WAF, headers, tech stack",
        "tools": ["httpx", "whatweb"],
        "module": web_fingerprint,
        "key": "web_fingerprint",
    },
    {
        "number": 5,
        "name": "Content Discovery",
        "description": "Dirs, files, backups, admin panels",
        "tools": ["ffuf"],
        "module": content_discovery,
        "key": "content_discovery",
    },
    {
        "number": 6,
        "name": "URL Collection",
        "description": "Crawl + historical URLs",
        "tools": ["katana", "gau", "waybackurls"],
        "module": url_collection,
        "key": "url_collection",
    },
    {
        "number": 7,
        "name": "Email Enumeration",
        "description": "Email formats, harvesting",
        "tools": ["theHarvester"],
        "module": email_enum,
        "key": "email_enum",
    },
    {
        "number": 8,
        "name": "Cloud Recon",
        "description": "S3, GCS, Azure, Firebase checks",
        "tools": ["cloud_enum"],
        "module": cloud_recon,
        "key": "cloud_recon",
    },
    {
        "number": 9,
        "name": "SSL/TLS Analysis",
        "description": "Cert info, SANs, weak ciphers",
        "tools": ["openssl", "sslscan"],
        "module": ssl_analysis,
        "key": "ssl_analysis",
    },
    {
        "number": 10,
        "name": "API Recon",
        "description": "Swagger, GraphQL, versioned endpoints",
        "tools": ["httpx"],
        "module": api_recon,
        "key": "api_recon",
    },
    {
        "number": 11,
        "name": "JavaScript Analysis",
        "description": "Endpoints, secrets in JS files",
        "tools": ["katana"],
        "module": js_analysis,
        "key": "js_analysis",
    },
    {
        "number": 12,
        "name": "Git Exposure",
        "description": ".git dir, secrets in repos",
        "tools": ["gitleaks", "trufflehog"],
        "module": git_exposure,
        "key": "git_exposure",
    },
    {
        "number": 13,
        "name": "Misc Checks",
        "description": "CORS, CSP, open redirect candidates",
        "tools": ["httpx"],
        "module": misc_checks,
        "key": "misc_checks",
    },
]


def build_module_table() -> Table:
    table = Table(title="Available Modules", show_lines=True, header_style="bold cyan")
    table.add_column("#", style="bold white", justify="center")
    table.add_column("Module Name", style="white")
    table.add_column("Description", style="white")
    table.add_column("Required Tool(s)", style="white")
    for module in MODULES:
        table.add_row(
            str(module["number"]),
            module["name"],
            module["description"],
            ", ".join(module["tools"]),
        )
    table.add_row(
        "0",
        "Run ALL modules",
        "Run everything above",
        "All tools",
    )
    return table


def prompt_target() -> tuple[list[str], str]:
    while True:
        answer = console.input("Enter target domain/IP (or path to a .txt file with multiple targets): ").strip()
        if not answer:
            print_error("Target input cannot be empty. Please enter a domain, IP, CIDR, or path to a text file.")
            continue
        path = Path(answer)
        if path.exists() and path.is_file():
            try:
                targets = validate_file_of_targets(str(path))
                return targets, str(path)
            except ValueError:
                continue
        try:
            target = validate_target(answer)
            return [target], target
        except ValueError:
            continue


def prompt_module_selection(config: dict) -> list[dict]:
    max_option = len(MODULES)
    while True:
        console.print(build_module_table())
        choice = console.input("Select modules to run (e.g. 1,2,5 or 1-4 or all): ").strip()
        if choice == "0":
            selections = list(range(1, max_option + 1))
        else:
            try:
                selections = validate_menu_choice(choice, max_option)
            except ValueError:
                continue
        selected_modules = [module for module in MODULES if module["number"] in selections]
        if not selected_modules:
            print_error("No valid modules selected. Choose one or more module numbers or use all.")
            continue
        required_tools = sorted({tool for module in selected_modules for tool in module["tools"]})
        missing = verify_tools(required_tools, config.get("tool_paths"))
        if missing:
            print_warning(
                "Some selected modules require tools that are not installed. "
                "If you continue, modules depending on missing tools will be skipped."
            )
            yes = prompt_yes_no("Skip missing tools and continue? (y/n): ")
            if not yes:
                continue
            selected_modules = [
                module for module in selected_modules if not any(tool in missing for tool in module["tools"])
            ]
            if not selected_modules:
                print_error("All selected modules require missing tools. Select a smaller set or install the missing tools.")
                continue
        return selected_modules


def prompt_yes_no(message: str) -> bool:
    while True:
        answer = console.input(message).strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print_error("Please enter y or n.")


def show_summary(targets: list[str], selected_modules: list[dict], session_dir: Path) -> None:
    lines = [
        f"Target(s): {', '.join(targets)}",
        f"Modules selected: {', '.join(module['name'] for module in selected_modules)}",
        f"Results will be saved to: {session_dir}"
    ]
    panel = Panel(Text("\n".join(lines), style="white"), title="Scan Summary", border_style="green")
    console.print(panel)


def run_scan(targets: list[str], selected_modules: list[dict], session_dir: Path, config: dict) -> None:
    total_steps = len(selected_modules) * len(targets)
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running modules…", total=total_steps)
        for module in selected_modules:
            for target in targets:
                description = f"{module['name']} on {target}"
                progress.update(task, description=description)
                try:
                    module["module"].run(target, session_dir, config)
                    file_path = session_dir / FILENAME_MAP.get(module["key"], f"{module['key']}.txt")
                    print_success(f"Completed {module['name']} for {target}: {file_path}")
                except Exception as exc:
                    print_error(f"{module['name']} failed for {target}: {exc}")
                progress.advance(task)


def main() -> None:
    print_banner()
    config = load_config()
    apply_first_run(config)
    print_startup_table(config.get("tool_paths"))
    check_ffuf_wordlist(config)
    targets, input_source = prompt_target()
    selected_modules = prompt_module_selection(config)
    session_dir = create_session_folder(
        targets[0] if len(targets) == 1 else "multiple_targets",
        results_root_name=get_results_dir(config),
    )
    show_summary(targets, selected_modules, session_dir)
    if not prompt_yes_no("Start scan? (y/n): "):
        print_info("Scan aborted by user.")
        return
    start_time = time.perf_counter()
    run_scan(targets, selected_modules, session_dir, config)
    elapsed = time.perf_counter() - start_time
    show_results_map(session_dir)
    print_success(f"Scan complete in {elapsed:.1f} seconds.")


if __name__ == "__main__":
    main()
