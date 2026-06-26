from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def print_banner():
    console = Console()

    swolf_art = r"""
  _______        ______  __     _____ 
 / ____\ \      / / __ \| |   |  ___|
 \___ \ \ \ /\ / / |  | | |   | |_   
  ___) | \ V  V /| |__| | |___|  _|  
 |____/   \_/\_/  \____/|_____|_|    """

    recon_art = r"""
 ____     _____     ____     ___     _   _ 
|  _ \   | ____|   / ___|   / _ \   | \ | |
| |_) |  |  _|    | |      | | | |  |  \| |
|  _ <   | |___|  | |___|  | |_| |  | |\  |
|_| \_\  |_____|   \____|   \___/   |_| \_|"""

    wolf_tag = "\n                    🐺  H U N T  T H E  T A R G E T  🐺\n"

    full = Text()
    full.append(swolf_art, style="bold cyan")
    full.append("\n")
    full.append(recon_art, style="bold red")
    full.append(wolf_tag, style="bold yellow")

    subtitle = Text(
        "   Automated Recon for Bug Bounty Hunters  —  Leave No Stone Unturned",
        style="bold white"
    )
    meta = Text(
        "   Version 0.1.0  |  Author: SWATIAN WOLF  |  github.com/swatian-wolf",
        style="dim cyan"
    )

    console.print(Panel(full, expand=False, border_style="cyan", padding=(0, 2)))
    console.print(subtitle)
    console.print(meta)
    console.print()


if __name__ == "__main__":
    print_banner()