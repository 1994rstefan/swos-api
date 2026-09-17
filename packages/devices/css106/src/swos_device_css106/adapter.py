"""CSS106 adapter for guarded reads and writes."""

from __future__ import annotations

from collections.abc import Callable

from swos_core.errors import ProtocolError
from swos_core.models import (
    AclRule,
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    ForwardingInfo,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PortInfo,
    PortNameUpdate,
    PortStatistics,
    PortVlanInfo,
    RstpInfo,
    SfpInfo,
    SnmpInfo,
    SystemInfo,
    VlanInfo,
)
from swos_core.transport import HttpTransport

from swos_device_css106.protocol import (
    MAX_PAYLOAD_BYTES,
    acl_rules_from_payload,
    dynamic_hosts_from_payload,
    encode_port_name_update,
    forwarding_from_payload,
    identity_from_system,
    igmp_groups_from_payload,
    link_write_state_from_payload,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    rstp_from_payloads,
    sfp_from_payload,
    snmp_from_payload,
    static_hosts_from_payload,
    system_info_from_payload,
    validate_port_name,
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
        features = {
            "acl",
            "forwarding",
            "hosts",
            "igmp_groups",
            "port_statistics",
            "ports",
            "rstp",
            "sfp",
            "snmp",
            "system",
            "vlan",
        }
        if self._identity.product_code == "CSS106-5G-1S":
            features.add("port_name_write")
        return DeviceCapabilities(features=frozenset(features))

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

    def get_snmp(self) -> SnmpInfo:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request("GET", "/snmp.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return snmp_from_payload(parse_payload(payload))

    def get_sfp(self) -> SfpInfo:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request("GET", "/sfp.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return sfp_from_payload(parse_payload(payload))

    def get_forwarding(self) -> ForwardingInfo:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request("GET", "/fwd.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return forwarding_from_payload(parse_payload(payload), self._identity)

    def get_igmp_groups(self) -> tuple[IgmpGroup, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request("GET", "/!igmp.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return igmp_groups_from_payload(parse_table_payload(payload), self._identity)

    def get_acl_rules(self) -> tuple[AclRule, ...]:
        with self._transport_factory(self._connection) as transport:
            payload = transport.request("GET", "/acl.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        return acl_rules_from_payload(parse_table_payload(payload), self._identity)

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

    def set_port_name(self, update: PortNameUpdate) -> OperationResult[PortInfo]:
        """Set one port name with a fresh identity check and full read-back."""

        validate_port_name(update.name)
        with self._transport_factory(self._connection) as transport:
            system_payload = transport.request(
                "GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            if identity_from_system(parse_payload(system_payload)) != self._identity:
                raise ProtocolError("CSS106 identity changed after device probing")

            before_payload = transport.request(
                "GET", "/link.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before_data = parse_payload(before_payload)
            before_ports = ports_from_link_payload(before_data, self._identity)
            if (
                update.number <= len(before_ports)
                and before_ports[update.number - 1].name == update.name
            ):
                return OperationResult[PortInfo](
                    changed=False,
                    value=before_ports[update.number - 1],
                )

            content, expected_state = encode_port_name_update(
                before_data,
                self._identity,
                update,
            )
            transport.request(
                "POST",
                "/link.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request(
                "GET", "/link.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )

        after_data = parse_payload(after_payload)
        if link_write_state_from_payload(after_data, self._identity) != expected_state:
            raise ProtocolError("CSS106 port-name write failed read-back verification")
        after_ports = ports_from_link_payload(after_data, self._identity)
        return OperationResult[PortInfo](
            changed=True,
            value=after_ports[update.number - 1],
        )
