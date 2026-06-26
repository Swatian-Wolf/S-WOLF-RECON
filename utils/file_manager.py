from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.tree import Tree

console = Console()

RESULTS_ROOT_NAME = "Results"
FILENAME_MAP = {
    "dns_recon": "dns_records.txt",
    "subdomain_enum": "subdomains.txt",
    "port_scan": "open_ports.txt",
    "web_fingerprint": "web_fingerprint.txt",
    "content_discovery": "directories.txt",
    "url_collection": "urls.txt",
    "email_enum": "emails.txt",
    "cloud_recon": "cloud_assets.txt",
    "ssl_analysis": "ssl_info.txt",
    "api_recon": "api_endpoints.txt",
    "js_analysis": "js_findings.txt",
    "git_exposure": "git_exposure.txt",
    "misc_checks": "misc_findings.txt",
    "scan_summary": "scan_summary.txt",
}


def _get_project_root() -> Path:
    """Return the absolute project root path for SWATIAN-WOLF RECON."""
    return Path(__file__).resolve().parents[1]


def ensure_results_root(project_root: Path | None = None, results_root_name: str | None = None) -> Path:
    """Ensure the top-level results directory exists and return its path."""
    root = project_root or _get_project_root()
    name = results_root_name or RESULTS_ROOT_NAME
    results_root = root / name
    results_root.mkdir(parents=True, exist_ok=True)
    return results_root


def create_session_folder(target: str, project_root: Path | None = None, results_root_name: str | None = None) -> Path:
    """Create a new results session folder for a scan target and return its path."""
    results_root = ensure_results_root(project_root, results_root_name)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_name = f"{_sanitize_target(target)}_{timestamp}"
    session_dir = results_root / session_name
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def _sanitize_target(target: str) -> str:
    """Sanitize a target string for use in a filesystem-safe session folder name."""
    sanitized = target.strip().replace(" ", "_")
    for char in "\\/:*?\"<>|":
        sanitized = sanitized.replace(char, "_")
    return sanitized


def create_session_folder(target: str, project_root: Path | None = None) -> Path:
    """Create a new Results/session folder for a scan target and return its path."""
    results_root = ensure_results_root(project_root)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_name = f"{_sanitize_target(target)}_{timestamp}"
    session_dir = results_root / session_name
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def _build_header(filename: str, module: str, target: str, date_time: datetime) -> str:
    """Build the standardized file header used for all scan result files."""
    return (
        f"# SWATIAN-WOLF RECON | Module: {module} | Target: {target} | Date: {date_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        "\n"
    )


def write_to_file(session_dir: str | Path, filename: str, content: str, module: str, target: str) -> Path:
    """Append content to a results file in the session folder, creating it with a header if needed."""
    session_path = Path(session_dir)
    session_path.mkdir(parents=True, exist_ok=True)
    result_file = session_path / filename
    now = datetime.now()
    if not result_file.exists():
        header = _build_header(filename, module, target, now)
        result_file.write_text(header, encoding="utf-8")
    with result_file.open("a", encoding="utf-8") as handle:
        handle.write(content.rstrip() + "\n")
    return result_file


def generate_scan_summary(session_dir: str | Path, target: str, modules_run: list[str]) -> Path:
    """Generate a scan_summary.txt file describing the session and the modules that were executed."""
    session_path = Path(session_dir)
    summary_path = session_path / FILENAME_MAP["scan_summary"]
    now = datetime.now()
    header = _build_header(summary_path.name, "scan_summary", target, now)
    lines = [header, "Scan Summary\n", f"Target: {target}\n", f"Session folder: {session_path}\n", f"Started: {now.strftime('%Y-%m-%d %H:%M:%S')}\n", "Modules run:\n"]
    for module in modules_run:
        filename = FILENAME_MAP.get(module, f"{module}.txt")
        lines.append(f" - {module}: {filename}\n")
    summary_path.write_text("".join(lines), encoding="utf-8")
    return summary_path


def _build_tree(path: Path, tree: Tree) -> None:
    """Recursively build a Rich Tree of files and directories starting from path."""
    for child in sorted(path.iterdir()):
        if child.is_dir():
            branch = tree.add(f"[bold blue]{child.name}[/]")
            _build_tree(child, branch)
        else:
            size_kb = child.stat().st_size / 1024
            tree.add(f"{child.name} ([green]{size_kb:.2f} KB[/])")


def show_results_map(session_dir: str | Path) -> None:
    """Print a Rich Tree showing all files in the session folder and their sizes."""
    session_path = Path(session_dir)
    if not session_path.exists():
        console.print(f"Session directory does not exist: {session_path}", style="bold red")
        return
    tree = Tree(f"[bold cyan]{session_path.name}[/]")
    _build_tree(session_path, tree)
    console.print(tree)
