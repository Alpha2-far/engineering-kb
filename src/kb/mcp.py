"""Alias et ré-export pour le serveur MCP de KB."""

from .server import (
    audit_code_snippet,
    get_security_rules,
    mcp,
    resolve_security_topic,
    run_server,
)

__all__ = [
    "mcp",
    "resolve_security_topic",
    "get_security_rules",
    "audit_code_snippet",
    "run_server",
]
