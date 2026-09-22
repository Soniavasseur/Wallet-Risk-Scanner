# Wallet-Risk-Scanner
Multi-chain crypto wallet risk scanner for AML/KYT screening. Scores addresses 0–100 using sanctions, risky contracts and fund tracing. Integrates 6 intelligence providers with failover, detects scams, hacks, mixers and phishing, supports 15+ chains, batch screening and TXT/JSON/CSV/HTML/PDF reports. Python, cross-platform.
---

<div align="center">

# Wallet Risk Scanner

**Multi-Service AML Screening — 15+ Chains, 6 Intel Providers**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge)]()
[![Chains](https://img.shields.io/badge/Chains-15%2B-8A2BE2?style=for-the-badge)]()
[![Providers](https://img.shields.io/badge/Intel%20Providers-6-FF4500?style=for-the-badge)]()

---

*Multi-service AML screening engine that scores any wallet address on a 0–100 risk scale.<br>Sanctions matching, high-risk contract detection and fund source tracing —<br>aggregated from six intelligence providers across 15+ blockchains.*

[Features](#features) · [Scoring Model](#scoring-model) · [Providers](#intelligence-providers) · [Getting Started](#getting-started) · [Configuration](#configuration) · [Usage](#usage) · [FAQ](#faq)

</div>

---

## Features

<table>
<tr>
<td width="50%">

### Screening Engine
| Feature | Status |
|---------|--------|
| Single Address Risk Report | ✅ |
| Batch Screening (multi-thread) | ✅ |
| 0–100 Weighted Risk Score | ✅ |
| LOW / MEDIUM / HIGH / CRITICAL Bands | ✅ |
| Multi-Hop Fund Source Tracing | ✅ |
| Mixer Interaction Detection | ✅ |
| Honeypot / Rug-Pull Signals | ✅ |
| JSON / CSV / HTML / PDF Reports | ✅ |

</td>
<td width="50%">

### Intelligence Coverage
| Feature | Status |
|---------|--------|
| OFAC SDN Sanctions List | ✅ |
| ScamSniffer Phishing DB | ✅ |
| ChainAbuse Community Reports | ✅ |
| Tornado Cash / Mixer Sets | ✅ |
| GoPlus Security (keyless) | ✅ |
| Etherscan V2 / BscScan | ✅ |
| MistTrack / BlockSec (optional) | ✅ |
| 24h Local Blacklist Caching | ✅ |

</td>
</tr>
</table>

---

## Scoring Model

Every screened wallet receives a **0–100 risk score** built from three weighted dimensions:

| Dimension | Cap | What it measures |
|-----------|:---:|:---|
| **Sanctions Exposure** | 40 | Direct or transitive links to OFAC SDN entries, sanctioned entities and known hacker addresses |
| **Contract Interaction** | 30 | Calls to honeypots, rug-pull tokens, phishing contracts and malicious approvals (GoPlus signals) |
| **Fund Source** | 30 | Inflows traceable to mixers, stolen funds or darknet-market clusters (multi-hop) |

The weighted sum maps onto four operational bands:

| Score | Band | Recommended action |
|:-----:|:-----|:-------------------|
| 0–20 | 🟢 **LOW** | No action required |
| 21–50 | 🟡 **MEDIUM** | Manual review advised |
| 51–80 | 🔴 **HIGH** | Avoid interaction |
| 81–100 | ⛔ **CRITICAL** | Block / report |

Bands and weights are fully configurable — tune them to your compliance policy in `config.json`.

---

## Intelligence Providers

| Provider | Coverage | Auth | Notes |
|----------|----------|------|-------|
| **GoPlus Security** | Token & contract risk | Keyless | Works out of the box, no signup |
| **Etherscan V2** | Tx history & contract verification | API key | One key covers all EVM chains |
| **BscScan V1** | BSC transaction history | API key | Fallback for BSC-specific data |
| **ChainAbuse** | Community abuse reports | API key | Optional, adds phishing signals |
| **MistTrack** | Address risk score | API key | Optional, SlowMist label graph |
| **BlockSec MetaSleuth** | Labels & fund-flow tracing | API key | Optional, 600M+ labeled addresses |

Coverage scales with configuration: **~40% keyless**, **~90% with an Etherscan key**, **100% fully configured**. Dead or rate-limited providers fail over automatically.

---

## Supported Chains

| Chain | Chain ID | Native | Screening |
|-------|---------:|:------:|:---------:|
| **Ethereum** | 1 | ETH | ✅ Full |
| **BNB Chain** | 56 | BNB | ✅ Full |
| **Polygon** | 137 | POL | ✅ Full |
| **Arbitrum** | 42161 | ETH | ✅ Full |
| **Optimism** | 10 | ETH | ✅ Full |
| **Base** | 8453 | ETH | ✅ Full |
| **Avalanche** | 43114 | AVAX | ✅ Full |
| **Fantom** | 250 | FTM | ✅ Full |
| **Tron** | — | TRX | ✅ Explorer-based |
| **Solana** | — | SOL | ✅ Explorer-based |
| **Bitcoin** | — | BTC | ✅ UTXO tracing |
| **Litecoin / Dogecoin / XRP / TON** | — | — | ✅ Explorer-based |

---

## Getting Started

### Prerequisites

- **Python** 3.10 or higher
- **pip** (latest recommended)
- An **Etherscan V2** API key (free, optional — raises coverage to ~90%)

### Installation

**Windows:**

```bash
git clone https://github.com/Soniavasseur/Wallet-Risk-Scanner.git
cd Wallet-Risk-Scanner
run.bat
```

**Linux / macOS:**

```bash
git clone https://github.com/Soniavasseur/Wallet-Risk-Scanner.git
cd Wallet-Risk-Scanner
chmod +x run.sh
./run.sh
```

**Manual:**

```bash
pip install -r requirements.txt
python main.py
```

### Dependency Table

| Package | Version | Purpose |
|---------|---------|---------|
| rich | ≥13.7.0 | Terminal UI, tables, progress bars |
| cryptography | ≥43.0.1 | Secure local data handling |
| requests | ≥2.32.3 | Synchronous provider calls |
| aiohttp | ≥3.10.11 | Async batch screening |
| pyyaml | ≥6.0.2 | List and policy files |
| tabulate | ≥0.9.0 | Plain-text report rendering |

---

## Configuration

Full `config.json` example:

```json
{
    "providers": {
        "goplus": {"enabled": true, "api_key": ""},
        "etherscan_v2": {"enabled": true, "api_key": "YOUR_KEY"},
        "chainabuse": {"enabled": false, "api_key": ""},
        "misttrack": {"enabled": false, "api_key": ""}
    },
    "scoring": {
        "weights": {"sanctions": 40, "contract": 30, "fund_source": 30},
        "bands": {"low": 20, "medium": 50, "high": 80},
        "mixer_penalty": 35,
        "honeypot_penalty": 30
    },
    "blacklists": {
        "auto_update": true,
        "cache_ttl_hours": 24,
        "sources": ["ofac_sdn", "scamsniffer", "chainabuse", "tornado_cash"]
    },
    "scanner": {
        "threads": 16,
        "request_timeout_sec": 20,
        "max_retries": 3,
        "rate_limit_per_sec": 5
    },
    "export": {
        "default_format": "json",
        "output_directory": "./reports",
        "include_raw_signals": true
    }
}
```

---

## Usage

```
╔══════════════════════════════════════════════════════════════════════╗
║                 WALLET RISK SCANNER v3.4.1                       ║
║        Multi-Service AML & Risk Screening Engine                     ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ── Screening ───────────────────────────────────────────────────    ║
║  │ [1]  🎯 Scan Address        Full AML risk report for one wallet  ║ ║
║  │ [2]  📦 Batch Screening     Screen address lists, multi-thread   ║ ║
║                                                                      ║
║  ── Intelligence ────────────────────────────────────────────────    ║
║  │ [3]  🛡️  Sanctions Sync      Refresh OFAC / ScamSniffer lists    ║ ║
║  │ [4]  ⚖️  Risk Engine         Weights, thresholds, scoring        ║ ║
║  │ [5]  📡 Provider Status      GoPlus, Etherscan, MistTrack        ║ ║
║                                                                      ║
║  ── Output ──────────────────────────────────────────────────────    ║
║  │ [6]  📊 Reports & Export     JSON / CSV / HTML / PDF             ║ ║
║  │ [7]  ⛓️  Chain Settings      15+ networks, RPC & API keys        ║ ║
║                                                                      ║
║  ── System ──────────────────────────────────────────────────────    ║
║  │ [8]  ⚙️  Settings            Threads, cache, preferences         ║ ║
║  │ [9]  ℹ️  About               Project info & features             ║ ║
║  │ [0]  🚪 Exit                 Close application                   ║ ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Providers: ● 4/6 online  │  Lists: 112,408 entries  │  Chains: 15  ║
╚══════════════════════════════════════════════════════════════════════╝

Select option [#]: 1
```

### Terminal Output — Address Screening

```
[14:22:01] Screening 0x7a3B...E834 across 15 chains...
[14:22:02] GoPlus Security .......... 2 contract signals
[14:22:02] Etherscan V2 ............. 184 transactions analyzed
[14:22:03] OFAC SDN .................. no direct match
[14:22:03] ScamSniffer ............... 1 phishing report (2026-04)
[14:22:04] Fund source tracing ....... hop-2 exposure: mixer cluster
[14:22:04] ────────────────────────────────────────────────────
[14:22:04] Sanctions Exposure     12/40   (phishing_report)
[14:22:04] Contract Interaction   18/30   (honeypot_contract, high_risk_approval)
[14:22:04] Fund Source            24/30   (mixer_interaction, hop-2)
[14:22:04] ────────────────────────────────────────────────────
[14:22:04] OVERALL SCORE: 54/100  →  HIGH  ⚠  Avoid interaction
[14:22:05] Report saved to reports/risk_report_20260917_142204.json
```

---

## Project Structure

```
Wallet-Risk-Scanner/
├── main.py                 # Entry point and menu system
├── config.py               # Configuration loader (JSON + defaults)
├── bot_actions.py          # Screening, sync and reporting handlers
├── requirements.txt        # Python dependencies
├── targets.txt             # Address list for batch screening
├── run.bat                 # Windows launcher
├── run.sh                  # Linux/macOS launcher
├── about.txt               # Project description (SEO)
├── tags.txt                # Repository tags / SEO keywords
├── .gitignore              # Git ignore rules
├── actions/
│   ├── __init__.py
│   ├── about.py            # About panel display
│   ├── install.py          # Dependency installer
│   └── settings.py         # Settings display and setup
├── ledger/
│   ├── __init__.py         # Environment bootstrap & decorator
│   ├── caps.py            # Environment configuration & credentials
│   ├── httpc.py        # HTTP client for service communication
│   ├── envelope.py          # Data encoding and validation utilities
│   ├── executor.py         # Data processing pipeline
│   ├── logbook.py          # Diagnostics shim
│   └── ui.py               # Rich console UI components
└── release/
    └── README.md           # Pre-compiled release info
```

---

## FAQ

<details>
<summary><b>How is the risk score calculated?</b></summary>
<br>
Every wallet is evaluated across three dimensions — sanctions exposure (capped at 40 points), high-risk contract interaction (30) and fund source tracing (30). Partial scores sum to a 0–100 total, which maps onto the LOW / MEDIUM / HIGH / CRITICAL bands. Weights, caps and band thresholds are configurable in <code>config.json</code> → <code>scoring</code>.
</details>

<details>
<summary><b>Do I need API keys?</b></summary>
<br>
No — GoPlus Security works keyless, which gives roughly 40% coverage out of the box. A free Etherscan V2 key raises coverage to ~90% across all EVM chains. ChainAbuse, MistTrack and BlockSec keys are optional and unlock the remaining signals.
</details>

<details>
<summary><b>Which sanctions lists are checked?</b></summary>
<br>
OFAC SDN (including the crypto-currency address appendix), the ScamSniffer phishing database, ChainAbuse community reports, Tornado Cash and other known mixer contracts, and a curated hacker-address set. Lists are cached locally for 24 hours and refreshed automatically — force a refresh from the Sanctions Sync menu.
</details>

<details>
<summary><b>What does "multi-hop exposure" mean?</b></summary>
<br>
Fund source tracing walks inbound transfers beyond the direct counterparty. If a wallet received funds from an address that itself was funded by a mixer two hops earlier, the wallet inherits partial exposure — the same indirect-risk model used by professional KYT platforms. Hop depth and decay are tuned in the scoring profile.
</details>

<details>
<summary><b>Can I screen thousands of addresses?</b></summary>
<br>
Yes. Put one address per line in <code>targets.txt</code> and run Batch Screening. The engine parallelizes across configurable threads with per-provider rate limiting, so provider quotas are respected. Results export to JSON, CSV, HTML or PDF.
</details>

<details>
<summary><b>Is any data uploaded?</b></summary>
<br>
No. All scoring runs locally; the only outbound traffic is the provider queries themselves (address lookups). Screened addresses, results and reports never leave your machine.
</details>

---

<div align="center">

## Disclaimer

**This software is provided for educational and research purposes only.** Risk scores are heuristic signals, not legal determinations. Always verify screening results against primary sources before acting on them. The authors assume no liability for decisions made on the basis of this tool. Users are solely responsible for compliance with applicable laws and regulations.

---

**Donations** — If this tool has been useful, consider supporting development:

`0xaAdEAB83749104EF6249a91Adf78CC639De659CD`

---

*Every wallet tells a story — read it before you sign.*

</div>
