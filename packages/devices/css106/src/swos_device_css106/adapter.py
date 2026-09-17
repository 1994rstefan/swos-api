"""Read-only CSS106 adapter."""

from __future__ import annotations

from collections.abc import Callable

from swos_core.errors import ProtocolError
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    HostEntry,
    PortInfo,
    PortStatistics,
    PortVlanInfo,
    RstpInfo,
    SystemInfo,
    VlanInfo,
)
from swos_core.transport import HttpTransport

from swos_device_css106.protocol import (
    MAX_PAYLOAD_BYTES,
    dynamic_hosts_from_payload,
    identity_from_system,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    rstp_from_payloads,
    static_hosts_from_payload,
    system_info_from_payload,
    vlans_from_payload,
)


class CSS106Adapter:
    """Normalize the tested CSS106 system endpoint."""

    def __init__(
        self,
        connection: DeviceConnection,
        identity: DeviceIdentity,
        transport_factory: Callable[[DeviceConnection], HttpTransport] = HttpTransport,
    ) -> None:
        self._connection = connection
        self._identity = identity
        self._transport_factory = transport_factory

    @property
    def identity(self) -> DeviceIdentity:
        return self._identity

    @property
    def capabilities(self) -> DeviceCapabilities:
        return DeviceCapabilities(
            features=frozenset({"hosts", "port_statistics", "ports", "rstp", "system", "vlan"})
        )

    def get_system_info(self) -> SystemInfo:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request(
                "GET",
                "/sys.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        data = parse_payload(payload)
        reported_identity = identity_from_system(data)
        if reported_identity != self._identity:
            raise ProtocolError("CSS106 identity changed after device probing")
        return system_info_from_payload(data, reported_identity)

    def get_ports(self) -> tuple[PortInfo, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request(
                "GET",
                "/link.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        return ports_from_link_payload(parse_payload(payload), self._identity)

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request(
                "GET",
                "/!stats.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        return port_statistics_from_payload(parse_payload(payload), self._identity)

    def get_hosts(self) -> tuple[HostEntry, ...]:
        with self._transport_factory(self._connection) as transport:
            static_payload = transport.request(
                "GET",
                "/host.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            dynamic_payload = transport.request(
                "GET",
                "/!dhost.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        static_hosts = static_hosts_from_payload(
            parse_table_payload(static_payload), self._identity
        )
        dynamic_hosts = dynamic_hosts_from_payload(
            parse_table_payload(dynamic_payload), self._identity
        )
        return static_hosts + dynamic_hosts

    def get_rstp(self) -> RstpInfo:
        with self._transport_factory(self._connection) as transport:
            system_payload = transport.request(
                "GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            system_data = parse_payload(system_payload)
            if identity_from_system(system_data) != self._identity:
                raise ProtocolError("CSS106 identity changed after device probing")
            rstp_payload = transport.request("GET", "/rstp.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return rstp_from_payloads(parse_payload(rstp_payload), system_data, self._identity)

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request(
                "GET",
                "/fwd.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        return port_vlans_from_forwarding_payload(parse_payload(payload), self._identity)

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request(
                "GET",
                "/vlan.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        return vlans_from_payload(parse_table_payload(payload), self._identity)
