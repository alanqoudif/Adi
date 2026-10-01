"""Deterministic nmap XML parser.

Never parse nmap's `-oN`/greppable text output — only the XML (`-oX -`)
format parsed here, via the standard library's ElementTree.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from adi.knowledge.observations import Observation, ObservationType


def parse(stdout: str, stderr: str, context: dict) -> list[Observation]:
    observations: list[Observation] = []
    if not stdout.strip():
        if context.get("exit_code", 0) != 0:
            observations.append(Observation(
                type=ObservationType.TOOL_ERROR,
                subject=context.get("target", ""),
                value={"tool": "nmap", "stderr": stderr.strip()[:2000]},
                source="nmap",
            ))
        return observations

    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as exc:
        return [Observation(
            type=ObservationType.TOOL_ERROR,
            subject=context.get("target", ""),
            value={"tool": "nmap", "error": f"XML parse error: {exc}"},
            source="nmap",
        )]

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = _primary_address(host_el)
        if address is None:
            continue

        observations.append(Observation(
            type=ObservationType.HOST_UP,
            subject=address,
            value={"address": address},
            source="nmap",
            confidence=1.0,
        ))

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            observations.append(Observation(
                type=ObservationType.OPEN_PORT,
                subject=f"{address}:{port}",
                value={
                    "host": address,
                    "port": port,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "state": "open",
                },
                source="nmap",
                confidence=1.0 if service_el is not None else 0.8,
            ))

    return observations


def _primary_address(host_el: ET.Element) -> str | None:
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            return addr_el.get("addr")
    first = host_el.find("address")
    return first.get("addr") if first is not None else None
