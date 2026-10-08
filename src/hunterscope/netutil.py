"""Small network helpers shared by the report and the redactor."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

# Deliberately NOT ipaddress.is_private: that also flags the RFC 5737 documentation
# ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) used in the sample data as "internal".
DEFAULT_INTERNAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")


def is_internal(ip: str, nets: Iterable[str] = DEFAULT_INTERNAL_NETS) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in nets:
        network = ipaddress.ip_network(net, strict=False)
        if addr.version == network.version and addr in network:
            return True
    return False
