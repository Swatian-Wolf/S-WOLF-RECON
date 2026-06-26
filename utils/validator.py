import re
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

from utils.display import print_error, print_info


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("No target provided. Enter a domain, IP, or CIDR like example.com or 192.168.1.0/24.")
    if " " in target:
        raise ValueError(f'Invalid target "{target}". Targets must not contain spaces.')
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(
                f'Invalid URL "{target}". Only http:// or https:// URL formats are accepted when using a full URL.'
            )
        cleaned = parsed.hostname
        note = "Removed protocol from target."
        if parsed.path and parsed.path not in ("", "/"):
            note = "Removed protocol and path from target."
        if parsed.port:
            note = "Removed protocol and port from target."
        print_info(f'{note} Using target: {cleaned}')
        return cleaned
    return target


def _validate_domain(domain: str) -> bool:
    if len(domain) > 253:
        return False
    if re.search(r"[^A-Za-z0-9.-]", domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.match(r"^[A-Za-z0-9-]+$", label):
            return False
    return True


def validate_target(target: str) -> str:
    """Validate a single target string and return the cleaned target."""
    try:
        cleaned = _normalize_target(target)
    except ValueError as exc:
        message = str(exc)
        print_error(message)
        raise ValueError(message)
    if "/" in cleaned:
        try:
            ip_network(cleaned, strict=False)
            return cleaned
        except ValueError:
            message = f'Invalid CIDR "{cleaned}". Use a format like 192.168.1.0/24.'
            print_error(message)
            raise ValueError(message)
    try:
        ip_address(cleaned)
        return cleaned
    except ValueError:
        pass
    if _validate_domain(cleaned):
        return cleaned.lower()
    message = f'Invalid target "{cleaned}". Enter a valid domain like example.com, a host like sub.example.com, an IPv4 address like 192.168.1.1, or a CIDR like 192.168.1.0/24.'
    print_error(message)
    raise ValueError(message)


def validate_target_list(targets: list) -> list[str]:
    """Validate a list of targets and return cleaned targets or raise on invalid entries."""
    if not isinstance(targets, list):
        message = "Target list must be provided as a list of strings."
        print_error(message)
        raise ValueError(message)
    cleaned_targets = []
    errors = []
    for raw in targets:
        try:
            cleaned_targets.append(validate_target(raw))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        message = "Multiple target validation errors:\n" + "\n".join(errors)
        print_error(message)
        raise ValueError(message)
    return cleaned_targets


def validate_menu_choice(choice: str, max_option: int) -> list[int]:
    """Validate a menu choice string and return a list of selected option numbers."""
    if not isinstance(choice, str) or not choice.strip():
        message = "No menu choice entered. Enter a number, range, comma-separated list, or all."
        print_error(message)
        raise ValueError(message)
    normalized = choice.strip().lower().replace(" ", "")
    if normalized == "all":
        return list(range(1, max_option + 1))
    invalid_chars = re.sub(r"[0-9,\-]", "", normalized)
    if invalid_chars:
        invalid = invalid_chars[0]
        message = (
            f'You entered "{choice}" — "{invalid}" is not a valid option character. '
            "Please use numbers only, like: 1,2,3 or 1-5 or all."
        )
        print_error(message)
        raise ValueError(message)
    selections = set()
    for part in normalized.split(","):
        if not part:
            message = f'Invalid menu input "{choice}". Empty segments are not allowed.'
            print_error(message)
            raise ValueError(message)
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) != 2 or not range_parts[0] or not range_parts[1]:
                message = f'Invalid range "{part}" in menu choice. Use a format like 1-5.'
                print_error(message)
                raise ValueError(message)
            try:
                start = int(range_parts[0])
                end = int(range_parts[1])
            except ValueError:
                message = f'You entered "{choice}" — "{part}" is not a valid range of numbers.'
                print_error(message)
                raise ValueError(message)
            if start > end:
                message = f'Invalid range "{part}". The first number must be lower than the second.'
                print_error(message)
                raise ValueError(message)
            if start < 1 or end > max_option:
                message = f'Range "{part}" is out of bounds. Choose values between 1 and {max_option}.'
                print_error(message)
                raise ValueError(message)
            selections.update(range(start, end + 1))
        else:
            try:
                value = int(part)
            except ValueError:
                message = f'You entered "{choice}" — "{part}" is not a valid option number. Please use numbers only, like: 1,2,3 or 1-5 or all.'
                print_error(message)
                raise ValueError(message)
            if value < 1 or value > max_option:
                message = f'Option "{value}" is out of range. Please choose a number between 1 and {max_option}. '
                f'Example: 1,2,3 or 1-5 or all.'
                print_error(message)
                raise ValueError(message)
            selections.add(value)
    return sorted(selections)


def validate_file_of_targets(filepath: str) -> list[str]:
    """Validate a file containing multiple targets and return a clean target list."""
    path = Path(filepath)
    if not path.exists():
        message = f'File not found: {filepath}'
        print_error(message)
        raise ValueError(message)
    if not path.is_file():
        message = f'Path is not a file: {filepath}'
        print_error(message)
        raise ValueError(message)
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        message = f'The file "{filepath}" is empty. Please provide one target per line.'
        print_error(message)
        raise ValueError(message)
    cleaned_targets = []
    errors = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            cleaned_targets.append(validate_target(stripped))
        except ValueError as exc:
            errors.append(f"Line {line_number}: {exc}")
    if not cleaned_targets and not errors:
        message = f'No valid targets found in file: {filepath}'
        print_error(message)
        raise ValueError(message)
    if errors:
        message = "Target file validation errors:\n" + "\n".join(errors)
        print_error(message)
        raise ValueError(message)
    return cleaned_targets
