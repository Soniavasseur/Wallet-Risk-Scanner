# -*- coding: utf-8 -*-
"""Configuration loader for Wallet Risk Scanner — JSON config + defaults."""

import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"

_DEFAULTS = {'providers': {'goplus': {'enabled': True, 'api_key': ''},
                   'etherscan_v2': {'enabled': True, 'api_key': ''},
                   'bscscan': {'enabled': True, 'api_key': ''},
                   'chainabuse': {'enabled': False, 'api_key': ''},
                   'misttrack': {'enabled': False, 'api_key': ''},
                   'blocksec': {'enabled': False, 'api_key': ''}},
     'scoring': {'weights': {'sanctions': 40, 'contract': 30, 'fund_source': 30},
                 'bands': {'low': 20, 'medium': 50, 'high': 80},
                 'mixer_penalty': 35,
                 'honeypot_penalty': 30},
     'blacklists': {'auto_update': True,
                    'cache_ttl_hours': 24,
                    'sources': ['ofac_sdn', 'scamsniffer', 'chainabuse', 'tornado_cash']},
     'scanner': {'threads': 16,
                 'request_timeout_sec': 20,
                 'max_retries': 3,
                 'rate_limit_per_sec': 5},
     'chains': {'ethereum': True,
                'bsc': True,
                'polygon': True,
                'arbitrum': True,
                'optimism': True,
                'base': True,
                'avalanche': True,
                'fantom': True,
                'tron': True,
                'solana': False,
                'bitcoin': False,
                'litecoin': False,
                'dogecoin': False,
                'xrp': False,
                'ton': False},
     'export': {'default_format': 'json',
                'output_directory': './reports',
                'include_raw_signals': True}}


def load_config() -> dict:
    """Load configuration from config.json, merging with defaults."""
    cfg = dict(_DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            _deep_merge(cfg, user_cfg)
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def _deep_merge(base: dict, override: dict):
    """Recursively merge override into base dict."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def save_config(cfg: dict):
    """Persist configuration to config.json."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
