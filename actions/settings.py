# -*- coding: utf-8 -*-
"""Settings action — configuration overview for Wallet Risk Scanner."""

from pathlib import Path

from rich.table import Table
from rich.panel import Panel
from rich import box

from ledger.ui import console, print_info, print_warning


def action_settings():
    """Display setup instructions: config.json sections and examples."""
    table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="bright_red",
        box=box.ROUNDED,
        title="[bold bright_red] ◈ CONFIGURATION ◈ [/]",
        title_style="bright_red",
    )
    table.add_column("Setting", style="bright_red")
    table.add_column("Description", style="dim")
    table.add_column("Example", style="bright_black")

    table.add_row('providers.goplus', 'GoPlus Security (keyless)', '"enabled": true')
    table.add_row('providers.etherscan_v2', 'Etherscan V2 multichain key', '"api_key": "YOUR_KEY"')
    table.add_row('providers.chainabuse', 'ChainAbuse community reports', '"enabled": true')
    table.add_row('scoring.weights', 'Dimension caps (40/30/30)', '"sanctions": 40')
    table.add_row('scoring.bands', 'Risk band thresholds', '"low": 20, "medium": 50')
    table.add_row('blacklists.cache_ttl_hours', 'Local list cache duration', '24')
    table.add_row('scanner.threads', 'Parallel screening threads', '16')
    table.add_row('chains', 'Enable/disable networks', '"ethereum": true')
    table.add_row('export.default_format', 'Report format', 'json / csv / html / pdf')

    panel = Panel(
        table,
        title="[bold bright_red] Wallet Risk Scanner Settings [/]",
        border_style="bright_red",
        box=box.DOUBLE,
    )

    console.print()
    console.print(panel)

    base_dir = Path(__file__).parent.parent
    config_path = base_dir / "config.json"

    console.print()
    console.print("[dim]Configuration files:[/]")
    console.print(f"  [bright_red]config.json[/]  → {config_path}")
    console.print()
    print_info('Provider keys go in config.json → providers.<name>.api_key.')
    print_info('GoPlus Security needs no key — coverage starts at ~40% out of the box.')
    print_warning("Keep API keys and secrets secure. Never commit config.json to version control.")
    print_info("Edit config files with any text editor (e.g. VS Code, Notepad).")
