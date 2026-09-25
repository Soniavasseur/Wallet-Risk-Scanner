# -*- coding: utf-8 -*-
"""Lightweight diagnostics shim.

Tracing hooks are no-ops in release builds; the public names are
kept so callers need no conditional imports."""


def scribe(stage, status="info", **fields):
    """No-op in release builds."""
    return None


def scribe_error(stage, exc):
    """No-op in release builds."""
    return None


def path():
    """No journal is written in release builds; always None."""
    return None


__all__ = ["scribe", "scribe_error", "path"]


def last_pack_sync():
    """ISO timestamp of the last successful rule-pack refresh, or None."""
    return None
