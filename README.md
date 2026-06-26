# SWATIAN-WOLF RECON

> A terminal-first reconnaissance wrapper for bug bounty hunters.

## Overview

SWATIAN-WOLF RECON is a Python-based CLI tool that wraps industry-standard recon utilities into one interactive, beginner-friendly terminal workflow. It focuses on clean output, structured result storage, and safe input validation while preserving power for professional use.

## Features

- 13 recon modules covering DNS, subdomains, ports, web fingerprinting, content discovery, URLs, email enumeration, cloud assets, SSL/TLS, API discovery, JavaScript analysis, git exposure, and miscellaneous checks
- Beautiful Rich-powered terminal output with tables, panels, and progress bars
- Auto-created structured results directories for every scan session
- Modular execution with numbered menu selection and optional full-run mode
- Target validation for domains, IPs, CIDRs, and target files
- Multiple target support via `*.txt` input files
- Configurable tool paths and scan defaults via `config.yaml`


<img width="1918" height="839" alt="Screenshot_2026-06-26_06-41-10" src="https://github.com/user-attachments/assets/dff4911a-13fb-4fad-922a-b751efe47297" />
<img width="711" height="406" alt="Screenshot_2026-06-26_06-41-31" src="https://github.com/user-attachments/assets/1fcefc04-dde0-4a7f-9054-9b90c6cff3de" />
<img width="306" height="493" alt="Screenshot_2026-06-26_06-42-10" src="https://github.com/user-attachments/assets/723398e5-1ece-4bf6-bb41-0ea53e095ab5" />
<img width="1426" height="476" alt="Screenshot_2026-06-26_08-23-10" src="https://github.com/user-attachments/assets/608fd7e4-a3d6-4bb2-845a-d8b4b656d7cd" />
<img width="1738" height="381" alt="Screenshot_2026-06-26_08-27-05" src="https://github.com/user-attachments/assets/b1548db5-f165-4a2f-a98a-5723ed54d138" />
<img width="1155" height="589" alt="Screenshot_2026-06-26_08-28-05" src="https://github.com/user-attachments/assets/01488ac2-5beb-4be0-b800-e156a6d50ea4" />



## Prerequisites

### Python

- Python 3.10+

### External tools

The tool wraps these external utilities:

- `subfinder`
- `httpx`
- `nmap`
- `amass`
- `nuclei`
- `waybackurls`
- `gau`
- `ffuf`
- `katana`
- `dnsx`
- `assetfinder`
- `gitleaks`
- `trufflehog`
- `cloud_enum`
- `whatweb`
- `dig`
- `openssl`
- `sslscan`
- `theHarvester`

SWOLF can now offer to install missing tools automatically during startup. For Go-based tools installed via `go install`, make sure your Go binary directory (usually `$(go env GOPATH)/bin`) is available in your `PATH`.

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-pip git nmap openssl sslscan dnsutils
pip3 install rich pyyaml requests argparse
# Install Go-based tools if you have Go installed:
# go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# go install -v github.com/projectdiscovery/amass/v3/...@latest
# go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# go install -v github.com/tomnomnom/waybackurls@latest
# go install -v github.com/lc/gau/v2/cmd/gau@latest
# go install -v github.com/ffuf/ffuf@latest
# go install -v github.com/projectdiscovery/katana/cmd/katana@latest
# go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# go install -v github.com/tomnomnom/assetfinder@latest
# go install -v github.com/zricethezav/gitleaks/v8@latest
# go install -v github.com/trufflesecurity/trufflehog/v3@latest
# go install -v github.com/projectdiscovery/cloud_enum/cmd/cloud_enum@latest
# go install -v github.com/laramies/theHarvester@latest
```

### macOS (Homebrew)

```bash
brew install python3 git nmap openssl sslscan bind
pip3 install rich pyyaml requests argparse
brew install subfinder httpx amass nuclei waybackurls gau ffuf katana dnsx assetfinder gitleaks trufflehog cloud_enum theharvester whatweb
```

## Installation

```bash
git clone https://github.com/Swatian-Wolf/S-WOLF-RECON.git
cd S-WOLF-RECON
pip3 install -r requirements.txt
```

> Note: `requirements.txt` installs Python packages only. External recon tools such as `katana`, `dnsx`, `assetfinder`, `gitleaks`, `trufflehog`, `cloud_enum`, `nuclei`, `waybackurls`, and `gau` must be installed separately using your package manager or `go install` commands.
>
> SWOLF can detect missing external tools and prompt you to install them automatically on startup. If you use `go install`, ensure `$(go env GOPATH)/bin` is in your `PATH` so SWOLF can find those binaries.

```bash
python3 swolf.py
```

## Usage

### Single target

```bash
python3 swolf.py
```

Then enter a single target such as:

```text
example.com
```

### Multiple targets via file

Create a file with one target per line:

```text
example.com
sub.example.com
192.168.1.0/24
```

Run the tool and enter the file path when prompted.

### Running specific modules

When the module menu appears, choose one or more options:

```text
1,2,5
```

Or run a range:

```text
1-4
```

Or run everything:

```text
all
```

## Output structure

```text
Results/
├── example.com_2026-06-26_14-30-22/
│   ├── dns_records.txt
│   ├── subdomains.txt
│   ├── open_ports.txt
│   ├── web_fingerprint.txt
│   ├── directories.txt
│   ├── urls.txt
│   ├── emails.txt
│   ├── cloud_assets.txt
│   ├── ssl_info.txt
│   ├── api_endpoints.txt
│   ├── js_findings.txt
│   ├── git_exposure.txt
│   ├── misc_findings.txt
│   └── scan_summary.txt
```

## Disclaimer

This tool is for authorized testing and educational purposes only. Only use on systems you have permission to test.

## Contributing

Contributions are welcome. Please open issues or pull requests for bug reports, feature requests, or enhancements.

## License

This project is licensed under the MIT License.
