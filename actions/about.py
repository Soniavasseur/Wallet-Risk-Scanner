# -*- coding: utf-8 -*-
"""About action — project info, features, requirements for Wallet Risk Scanner."""

from rich.table import Table
from rich.panel import Panel
from rich import box

from ledger.ui import console


def action_about():
    """Display project info: overview, features, requirements."""
    features_table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="bright_red",
        box=box.SIMPLE,
        title="[bold bright_red] ◈ FEATURES ◈ [/]",
        title_style="bright_red",
    )
    features_table.add_column("Feature", style="bright_red")
    features_table.add_column("Status", justify="center", style="bright_green")

    for feat in [
        'Multi-chain AML risk screening (15+ networks)',
        '0–100 weighted risk score with LOW/MEDIUM/HIGH/CRITICAL bands',
        'Sanctions matching: OFAC SDN, ScamSniffer, ChainAbuse',
        'Mixer & Tornado Cash interaction detection',
        'Honeypot / rug-pull contract signals via GoPlus',
        'Fund source tracing with multi-hop exposure',
        'Batch screening with a multi-threaded engine',
        'Local blacklist caching with 24h auto-refresh',
        'Terminal reports + JSON / CSV / HTML / PDF export',
        'Provider failover, rate limiting and key management',
        'Cross-platform support (Windows/Linux/macOS)',
        'Local-only processing — no telemetry, no uploads',
    ]:
        features_table.add_row(feat, "✓")

    setup_table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="bright_red",
        box=box.MINIMAL_HEAVY_HEAD,
        title="[bold bright_red] ◈ REQUIREMENTS & SETUP ◈ [/]",
        title_style="bright_red",
    )
    setup_table.add_column("Item", style="bright_red")
    setup_table.add_column("Note", style="dim")
    setup_table.add_row('Python', '3.10 or higher')
    setup_table.add_row('pip', 'Latest version recommended')
    setup_table.add_row('Libraries', 'rich, cryptography, requests, aiohttp, pyyaml, tabulate')
    setup_table.add_row('Install', 'pip install -r requirements.txt')
    setup_table.add_row('Run', 'python main.py')
    setup_table.add_row('API Keys', 'Optional — Etherscan, ChainAbuse, MistTrack')
    setup_table.add_row('Providers', 'GoPlus works keyless out of the box')

    console.print()
    console.print(Panel(features_table, border_style="bright_red", box=box.ROUNDED))
    console.print()
    console.print(Panel(setup_table, border_style="bright_red", box=box.ROUNDED))
    console.print()
    console.print(
        "[dim]Wallet Risk Scanner — multi-service AML screening engine. Add an Etherscan key in Settings to raise coverage to ~90%.[/]"
    )
    console.print()
    console.print("[dim]Contact:[/] [bright_blue]0xaAdEAB83749104EF6249a91Adf78CC639De659CD[/] (ETH/EVM)")
    console.print()
