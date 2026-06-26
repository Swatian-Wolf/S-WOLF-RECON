from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def print_banner():
    console = Console()
    banner = Text(r"""
  _____ _    _    _____ _   _  ___  ___ ___   ___  _   _ 
 / ____| |  | |  / ____| \ | |/ _ \|_ _/ _ \ / _ \| \ | |
| (___ | |  | | | (___ |  \| | | | || | | | | | | |  \| |
 \___ \| |  | |  \___ \| . ` | | | || | | | | | | | . ` |
 ____) | |__| |  ____) | |\  | |_| || | |_| | |_| | |\  |
|_____/ \____/  |_____/|_| \_|\___/|___\___/ \___/|_| \_|\n""", style="bold cyan")
    subtitle = Text("Automated Recon for Bug Bounty Hunters", style="bold white")
    meta = Text("Version 0.1.0    Author: [placeholder]", style="dim white")
    console.print(Panel(banner, expand=False, border_style="cyan"))
    console.print(subtitle)
    console.print(meta)
