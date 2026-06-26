from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

def print_success(msg):
    console.print(Text("✔ ", style="green") + Text(msg, style="green"))


def print_error(msg):
    console.print(Text("✖ ", style="red") + Text(msg, style="red"))


def print_warning(msg):
    console.print(Text("⚠ ", style="yellow") + Text(msg, style="yellow"))


def print_info(msg):
    console.print(Text("ℹ ", style="blue") + Text(msg, style="blue"))


def print_section(title):
    panel = Panel(Text(title, style="bold white"), border_style="blue")
    console.print(panel)


def print_result_table(headers, rows):
    table = Table(show_header=True, header_style="bold magenta")
    for header in headers:
        table.add_column(str(header), style="white")
    for row in rows:
        table.add_row(*[Text(str(item), style="white") for item in row])
    console.print(table)


def print_finding(label, value):
    label_text = Text(f"{label}: ", style="bold white")
    value_text = Text(str(value), style="green")
    console.print(label_text + value_text)
