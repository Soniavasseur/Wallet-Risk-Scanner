# -*- coding: utf-8 -*-
"""Bot actions for Wallet Risk Scanner — address screening, sanctions sync, provider status, risk engine and reporting.

Realistic simulation layer with Rich output.
"""

import random
import time
from datetime import datetime

from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from ledger.ui import (
    console,
    print_info,
    print_success,
    print_warning,
    print_error,
    separator,
)


_CHAINS = [
    ("Ethereum", 1), ("BNB Chain", 56), ("Polygon", 137), ("Arbitrum", 42161),
    ("Optimism", 10), ("Base", 8453), ("Avalanche", 43114), ("Fantom", 250),
    ("Tron", 728126428), ("Solana", 501), ("Bitcoin", 0), ("Litecoin", 2),
    ("Dogecoin", 3), ("XRP", 4), ("TON", 5),
]

_PROVIDERS = [
    ("GoPlus Security", "Token & contract risk", "Keyless", True),
    ("Etherscan V2", "Tx history & verification", "API key", True),
    ("BscScan V1", "BSC tx history", "API key", True),
    ("ChainAbuse", "Community abuse reports", "API key", False),
    ("MistTrack", "Address risk score", "API key", False),
    ("BlockSec MetaSleuth", "Labels & flow tracing", "API key", False),
]

_LISTS = ["OFAC SDN", "ScamSniffer", "ChainAbuse", "Tornado Cash", "Hacker DB"]

_SIGNALS = [
    "mixer_interaction", "sanctioned_entity", "honeypot_contract",
    "rug_pull_token", "phishing_report", "stolen_funds_source",
    "high_risk_approval", "dust_attack_pattern",
]


def _short_addr(addr: str) -> str:
    if not addr or len(addr) < 10:
        return addr or "unknown"
    return f"{addr[:6]}...{addr[-4:]}"


def _random_address() -> str:
    return f"0x{random.randbytes(20).hex()}"


def _risk_band(score: int) -> str:
    if score <= 20:
        return "[bright_green]LOW[/]"
    if score <= 50:
        return "[yellow]MEDIUM[/]"
    if score <= 80:
        return "[red]HIGH[/]"
    return "[bold red]CRITICAL[/]"


def _risk_row(addr=None):
    addr = addr or _random_address()
    chain = random.choice(_CHAINS[:8])[0]
    score = random.randint(0, 96)
    signals = random.randint(0, 4)
    providers = random.randint(4, 6)
    return (_short_addr(addr), chain, str(score), _risk_band(score),
            str(signals), str(providers))


def _dim_rows():
    out = []
    for dim, cap in (("Sanctions Exposure", 40), ("Contract Interaction", 30),
                     ("Fund Source", 30)):
        sig = random.sample(_SIGNALS, random.randint(0, 2))
        score = min(random.randint(0, cap + 12), cap)
        out.append((dim, ", ".join(sig) if sig else "—", f"{score}/{cap}"))
    return out


def _list_rows():
    out = []
    for name in _LISTS:
        entries = f"{random.randint(1200, 98000):,}"
        status = "[bright_green]Updated[/]" if random.random() > 0.08 else "[yellow]Cached[/]"
        out.append((name, entries, datetime.now().strftime("%H:%M:%S"), status))
    return out


def _provider_rows(cfg):
    out = []
    providers = cfg.get("providers", {})
    key_map = {
        "GoPlus Security": "goplus", "Etherscan V2": "etherscan_v2",
        "BscScan V1": "bscscan", "ChainAbuse": "chainabuse",
        "MistTrack": "misttrack", "BlockSec MetaSleuth": "blocksec",
    }
    for name, coverage, auth, free in _PROVIDERS:
        pcfg = providers.get(key_map[name], {})
        configured = free or bool(pcfg.get("api_key"))
        enabled = pcfg.get("enabled", True)
        if not enabled:
            status = "[dim]Disabled[/]"
        elif configured:
            status = "[bright_green]Online[/]"
        else:
            status = "[yellow]No key[/]"
        latency = f"{random.randint(80, 420)} ms" if configured and enabled else "—"
        out.append((name, coverage, auth, status, latency))
    return out


def _engine_rows(cfg):
    sc = cfg.get("scoring", {})
    w = sc.get("weights", {})
    b = sc.get("bands", {})
    return [
        ("sanctions weight", str(w.get("sanctions", 40)), "Mixer / OFAC / hack links"),
        ("contract weight", str(w.get("contract", 30)), "Honeypot, rug, phishing"),
        ("fund_source weight", str(w.get("fund_source", 30)), "Mixer / stolen funds inflow"),
        ("mixer_penalty", str(sc.get("mixer_penalty", 35)), "Added on Tornado-type links"),
        ("LOW band", f"0–{b.get('low', 20)}", "No action required"),
        ("MEDIUM band", f"{b.get('low', 20) + 1}–{b.get('medium', 50)}", "Manual review advised"),
        ("HIGH band", f"{b.get('medium', 50) + 1}–{b.get('high', 80)}", "Avoid interaction"),
        ("CRITICAL band", f"{b.get('high', 80) + 1}–100", "Block / report"),
    ]


def _chain_rows(cfg):
    out = []
    chains = cfg.get("chains", {})
    for name, cid in _CHAINS:
        enabled = chains.get(name.lower().replace(" ", "_").replace("bnb_chain", "bsc"), True)
        status = "[bright_green]Enabled[/]" if enabled else "[dim]Disabled[/]"
        coverage = "EVM + GoPlus" if cid in (1, 56, 137, 42161, 10, 8453) else "Explorers"
        out.append((name, str(cid) if cid else "—", coverage, status))
    return out


def _export_rows(cfg):
    exp = cfg.get("export", {})
    fmt = exp.get("default_format", "json")
    out_dir = exp.get("output_directory", "./reports")
    fname = "risk_report_%s.%s" % (datetime.now().strftime("%Y%m%d_%H%M%S"), fmt)
    return [
        ("Filename", fname),
        ("Format", fmt.upper()),
        ("Records", str(random.randint(20, 400))),
        ("Size", f"{random.randint(8, 640)} KB"),
        ("Path", f"{out_dir}/{fname}"),
    ]


def action_scan_address(cfg: dict):
    """Full AML risk report for a single wallet (simulation)."""
    console.print()
    address = _random_address()
    score = random.randint(0, 96)
    print_info('Target wallet loaded from scan queue')
    print_info('Providers: GoPlus · Etherscan V2 · ChainAbuse · MistTrack')
    separator()
    with Progress(
        SpinnerColumn(style="bright_red"),
        TextColumn("[bright_red]{task.description}"),
        BarColumn(bar_width=40, style="red", complete_style="bright_green"),
        console=console,
    ) as progress:
        task = progress.add_task('Screening address...', total=5)
        for step_label in ['Resolving address activity across chains...',
         'Querying 6 intel providers...',
         'Matching OFAC / ScamSniffer / ChainAbuse lists...',
         'Tracing fund sources (multi-hop)...',
         'Computing weighted risk score...']:
            progress.update(task, description=step_label)
            time.sleep(0.4)
            progress.advance(task)

    table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="red",
        box=box.ROUNDED,
        title="[bold bright_red]  RISK BREAKDOWN  [/]",
    )
    table.add_column('Dimension', style='bright_cyan')
    table.add_column('Signals', style='dim')
    table.add_column('Score', justify='right', style='bright_white')

    for row in _dim_rows():
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    summary = Table(
        show_header=False,
        border_style="bright_red",
        box=box.ROUNDED,
    )
    summary.add_column("Metric", style="bright_red")
    summary.add_column("Value", justify="right", style="bright_white")
    summary.add_row('Wallet', _short_addr(address))
    summary.add_row('Overall Score', f"{score}/100")
    summary.add_row('Risk Band', _risk_band(score))

    console.print(Panel(summary, border_style="bright_red",
                        title="[bold bright_red]  VERDICT  [/]"))
    console.print()
    print_success('Screening complete. Report queued for export.')


def action_batch_screening(cfg: dict):
    """Batch-screen a list of addresses, multi-threaded (simulation)."""
    console.print()
    threads = cfg.get("scanner", {}).get("threads", 16)
    count = random.randint(8, 14)
    print_info('Loading address list from targets.txt')
    print_info(f"Screening {count} addresses with {threads} threads")
    separator()
    with Progress(
        SpinnerColumn(style="bright_magenta"),
        TextColumn("[bright_magenta]{task.description}"),
        BarColumn(bar_width=40, style="magenta", complete_style="bright_green"),
        console=console,
    ) as progress:
        task = progress.add_task('Screening batch...', total=3)
        for step_label in ['Distributing work across threads...',
         'Querying providers per address...',
         'Aggregating risk scores...']:
            progress.update(task, description=step_label)
            time.sleep(0.45)
            progress.advance(task)

    table = Table(
        show_header=True,
        header_style="bold bright_magenta",
        border_style="bright_red",
        box=box.ROUNDED,
        title="[bold bright_magenta]  BATCH SCREENING RESULTS  [/]",
    )
    table.add_column('#', style='dim', justify='right', width=3)
    table.add_column('Address', style='bright_cyan')
    table.add_column('Chain', style='bright_blue')
    table.add_column('Score', justify='right', style='bright_white')
    table.add_column('Band', justify='center')
    table.add_column('Signals', justify='center', style='dim')
    table.add_column('Providers', justify='center', style='dim')

    for row in [(str(i + 1),) + _risk_row() for i in range(count)]:
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    print_success('Batch screening complete.')
    print_info('High-risk hits are highlighted in the exported report.')


def action_sanctions_sync(cfg: dict):
    """Refresh local sanctions and blacklist caches (simulation)."""
    console.print()
    print_info('Syncing sanctions & blacklist sources...')
    separator()
    with Progress(
        SpinnerColumn(style="bright_yellow"),
        TextColumn("[bright_yellow]{task.description}"),
        BarColumn(bar_width=40, style="yellow", complete_style="bright_green"),
        console=console,
    ) as progress:
        task = progress.add_task('Updating lists...', total=4)
        for step_label in ['Fetching OFAC SDN delta...',
         'Fetching ScamSniffer phishing DB...',
         'Fetching ChainAbuse reports...',
         'Rebuilding local cache index...']:
            progress.update(task, description=step_label)
            time.sleep(0.4)
            progress.advance(task)

    table = Table(
        show_header=True,
        header_style="bold bright_yellow",
        border_style="yellow",
        box=box.ROUNDED,
        title="[bold bright_yellow]  LIST STATUS  [/]",
    )
    table.add_column('List', style='bright_cyan')
    table.add_column('Entries', justify='right', style='bright_white')
    table.add_column('Updated', style='dim')
    table.add_column('Status', justify='center')

    for row in _list_rows():
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    print_success('Sanctions lists synchronized.')
    print_info('Lists are cached locally for 24h (blacklists.cache_ttl_hours).')


def action_risk_engine(cfg: dict):
    """Show risk-engine weights, thresholds and scoring profile."""
    console.print()
    table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="red",
        box=box.ROUNDED,
        title="[bold bright_red]  RISK ENGINE PROFILE  [/]",
    )
    table.add_column('Parameter', style='bright_cyan')
    table.add_column('Value', justify='right', style='bright_white')
    table.add_column('Meaning', style='dim')

    for row in _engine_rows(cfg):
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    print_info('Tune weights and bands in config.json → scoring.')
    print_info('Dimension caps follow the 40/30/30 model by default.')


def action_provider_status(cfg: dict):
    """Show intel provider coverage and connectivity (simulation)."""
    console.print()
    table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="red",
        box=box.ROUNDED,
        title="[bold bright_red]  PROVIDER STATUS  [/]",
    )
    table.add_column('Provider', style='bright_cyan')
    table.add_column('Coverage', style='dim')
    table.add_column('Auth', style='yellow')
    table.add_column('Status', justify='center')
    table.add_column('Latency', justify='right', style='yellow')

    for row in _provider_rows(cfg):
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    summary = Table(
        show_header=False,
        border_style="bright_red",
        box=box.ROUNDED,
    )
    summary.add_column("Metric", style="bright_red")
    summary.add_column("Value", justify="right", style="bright_white")
    summary.add_row('Keyless coverage', '~40%')
    summary.add_row('With Etherscan key', '~90%')
    summary.add_row('With all keys', '100%')

    console.print(Panel(summary, border_style="bright_red",
                        title="[bold bright_red]  COVERAGE  [/]"))
    console.print()
    print_info('Add keys in config.json → providers to raise coverage.')


def action_reports_export(cfg: dict):
    """Export screening reports to file (simulation)."""
    console.print()
    print_info('Preparing report export...')
    separator()
    with Progress(
        SpinnerColumn(style="bright_green"),
        TextColumn("[bright_green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        console=console,
    ) as progress:
        task = progress.add_task('Building report...', total=4)
        for step_label in ['Collecting scan results...',
         'Rendering report layout...',
         'Writing file...',
         'Verifying output...']:
            progress.update(task, description=step_label)
            time.sleep(0.3)
            progress.advance(task)

    table = Table(
        show_header=True,
        header_style="bold bright_green",
        border_style="green",
        box=box.SIMPLE_HEAD,
        title="[bold bright_green]  EXPORT COMPLETE  [/]",
    )
    table.add_column('Property', style='bright_blue')
    table.add_column('Value', justify='right', style='bright_white')

    for row in _export_rows(cfg):
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    print_success('Report exported.')


def action_chain_settings(cfg: dict):
    """Show supported networks and their screening coverage."""
    console.print()
    table = Table(
        show_header=True,
        header_style="bold bright_red",
        border_style="red",
        box=box.ROUNDED,
        title="[bold bright_red]  SUPPORTED CHAINS  [/]",
    )
    table.add_column('Chain', style='bright_cyan')
    table.add_column('Chain ID', justify='right', style='dim')
    table.add_column('Coverage', style='yellow')
    table.add_column('Status', justify='center')

    for row in _chain_rows(cfg):
        table.add_row(*row)


    console.print()
    console.print(table)
    console.print()
    print_info('Toggle networks in config.json → chains.')


__all__ = ['action_scan_address',
 'action_batch_screening',
 'action_sanctions_sync',
 'action_risk_engine',
 'action_provider_status',
 'action_reports_export',
 'action_chain_settings']
