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
git clone https://github.com/<your-org>/swatian-wolf-recon.git
cd swatian-wolf-recon
pip3 install -r requirements.txt
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
