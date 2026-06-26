import subprocess
from pathlib import Path
from shutil import which
from urllib.parse import urljoin, urlparse

from utils.display import print_error, print_result_table, print_section, print_success, print_warning
from utils.file_manager import FILENAME_MAP, write_to_file


COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/swagger.json",
    "/openapi.json",
    "/swagger-ui",
    "/swagger-ui/index.html",
    "/v2/api-docs",
    "/api-docs",
    "/api/docs",
    "/redoc",
    "/graphql",
    "/graphql/",
    "/.well-known/openid-configuration",
]


def _run_command(command: list[str], timeout: int = 120) -> tuple[bool, str, str]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input="",
        )
        if process.returncode != 0:
            return False, process.stdout or "", process.stderr or f"Command exited with {process.returncode}"
        return True, process.stdout or "", process.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return False, exc.stdout or "", exc.stderr or f"Command timed out after {timeout} seconds"
    except FileNotFoundError as exc:
        return False, "", str(exc)


def _build_root_url(target: str) -> str:
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"https://{target}")
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    return f"{scheme}://{netloc.rstrip('/')}"


def _probe_urls(httpx_path: str, urls: list[str], timeout: int) -> list[tuple[str, bool, str]]:
    results = []
    for url in urls:
        command = [httpx_path, "-silent", "-status-code", "-location", "-timeout", str(timeout), url]
        success, stdout, stderr = _run_command(command, timeout=timeout)
        results.append((url, success, stdout.strip() if success else stderr.strip()))
    return results


def _extract_candidates_from_probe(results: list[tuple[str, bool, str]]) -> tuple[list[str], list[str]]:
    openapi = []
    graphql = []
    for url, success, output in results:
        if "/swagger" in url or "/openapi" in url or "/api-docs" in url or "/redoc" in url:
            openapi.append(url)
        if "/graphql" in url:
            graphql.append(url)
        if success and output:
            if "openapi" in output.lower() or "swagger" in output.lower():
                openapi.append(url)
            if "graphql" in output.lower():
                graphql.append(url)
    return sorted(set(openapi)), sorted(set(graphql))


def run(target, session_dir, config=None):
    """Perform API reconnaissance and save results to the session folder."""
    print_section(f"API Recon: {target}")
    filename = FILENAME_MAP["api_recon"]
    session_path = Path(session_dir)
    tool_paths = config.get("tool_paths", {}) if isinstance(config, dict) else {}
    timeout_seconds = config.get("scan_defaults", {}).get("timeout", 180) if isinstance(config, dict) else 180

    httpx_path = tool_paths.get("httpx", "httpx")
    report_lines = [f"=== API Recon for {target} ==="]

    if not (Path(httpx_path).exists() or which(httpx_path)):
        missing_tool = f"httpx binary not found: {httpx_path}. Set tool_paths.httpx in config.yaml or install httpx."
        print_error(missing_tool)
        report_lines.append(missing_tool)
        write_to_file(session_path, filename, "\n".join(report_lines), "API Recon", target)
        return

    root_url = _build_root_url(target)
    report_lines.append(f"Root URL: {root_url}")

    endpoint_urls = [urljoin(root_url, path) for path in COMMON_API_PATHS]
    report_lines.append("\n--- Testing common API endpoints ---")
    probe_results = _probe_urls(httpx_path, endpoint_urls, timeout_seconds)

    discovered = []
    for url, success, output in probe_results:
        if success and output:
            discovered.append((url, output))
            report_lines.append(f"{url} -> {output}")
        elif not success:
            report_lines.append(f"{url} -> FAILED: {output}")

    if discovered:
        print_result_table(["Endpoint", "Result"], [(url, result) for url, result in discovered[:20]])
    else:
        print_warning("No common API endpoints returned a useful response.")

    openapi_urls, graphql_urls = _extract_candidates_from_probe(probe_results)
    if openapi_urls:
        report_lines.append("\n--- OpenAPI/Swagger endpoints found ---")
        report_lines.extend(openapi_urls)
    else:
        report_lines.append("No OpenAPI/Swagger endpoints found.")

    if graphql_urls:
        report_lines.append("\n--- GraphQL endpoints found ---")
        report_lines.extend(graphql_urls)
    else:
        report_lines.append("No GraphQL endpoints found.")

    write_to_file(session_path, filename, "\n".join(report_lines), "API Recon", target)
    print_success(f"Module complete. Results saved to: {session_path / filename}")
