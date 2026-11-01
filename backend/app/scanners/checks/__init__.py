"""Importing this package registers all bundled checks."""
from app.scanners.checks import http_headers, port_discovery, tls_check  # noqa: F401
