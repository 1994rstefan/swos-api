"""CSS106 adapter for guarded reads and writes."""

from __future__ import annotations

from collections.abc import Callable

from swos_core.errors import InvalidOperationError, ProtocolError
from swos_core.models import (
    AclRule,
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForwardingInfo,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PortConfigurationUpdate,
    PortInfo,
    PortNameUpdate,
    PortStatistics,
    PortVlanInfo,
    RstpInfo,
    SfpInfo,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemInfo,
    VlanInfo,
)
from swos_core.transport import HttpTransport

from swos_device_css106.protocol import (
    MAX_PAYLOAD_BYTES,
    acl_rules_from_payload,
    dynamic_hosts_from_payload,
    encode_acl_rules,
    encode_device_name_update,
    encode_port_configuration_update,
    encode_port_name_update,
    encode_snmp_metadata_update,
    encode_static_hosts,
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
    snmp_write_state_from_payload,
    static_hosts_from_payload,
    system_info_from_payload,
    system_name_write_state_from_payload,
    validate_device_name,
    validate_port_name,
    validate_snmp_metadata,
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
            features.update(
                {
                    "device_name_write",
                    "port_configuration_write",
                    "port_name_write",
                    "snmp_metadata_write",
                    "static_hosts_write",
                }
            )
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
            content, expected_state = encode_port_name_update(
                before_data,
                self._identity,
                update,
            )
            if (
                update.number <= len(before_ports)
                and before_ports[update.number - 1].name == update.name
            ):
                return OperationResult[PortInfo](
                    changed=False,
                    value=before_ports[update.number - 1],
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

    def set_port_configuration(self, update: PortConfigurationUpdate) -> OperationResult[PortInfo]:
        """Configure one Ethernet port with identity and complete-state guards."""

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
            before_state = link_write_state_from_payload(before_data, self._identity)
            before_ports = ports_from_link_payload(before_data, self._identity)
            content, expected_state = encode_port_configuration_update(
                before_data,
                self._identity,
                update,
            )
            before_port = before_ports[update.number - 1]
            if expected_state == before_state:
                return OperationResult[PortInfo](changed=False, value=before_port)
            if before_port.link_up and _changes_active_port_connectivity(update, before_port):
                raise InvalidOperationError(
                    f"Port {update.number} is link-up; active ports cannot be disabled or "
                    "have negotiation changed"
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
            raise ProtocolError("CSS106 port-configuration write failed read-back verification")
        after_ports = ports_from_link_payload(after_data, self._identity)
        return OperationResult[PortInfo](
            changed=True,
            value=after_ports[update.number - 1],
        )

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        """Set the device name with a fresh identity check and sparse write."""

        validate_device_name(update.name)
        with self._transport_factory(self._connection) as transport:
            before_payload = transport.request(
                "GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before_data = parse_payload(before_payload)
            reported_identity = identity_from_system(before_data)
            if reported_identity != self._identity:
                raise ProtocolError("CSS106 identity changed after device probing")
            before_info = system_info_from_payload(before_data, reported_identity)
            content, expected_state = encode_device_name_update(before_data, update)
            if before_info.name == update.name:
                return OperationResult[SystemInfo](changed=False, value=before_info)

            transport.request(
                "POST",
                "/sys.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)

        after_data = parse_payload(after_payload)
        reported_identity = identity_from_system(after_data)
        if reported_identity != self._identity:
            raise ProtocolError("CSS106 identity changed after device-name write")
        if system_name_write_state_from_payload(after_data) != expected_state:
            raise ProtocolError("CSS106 device-name write failed read-back verification")
        after_info = system_info_from_payload(after_data, reported_identity)
        if _system_configuration(after_info) != _system_configuration(before_info):
            raise ProtocolError("CSS106 device-name write changed unrelated system configuration")
        return OperationResult[SystemInfo](
            changed=True,
            value=after_info,
        )

    def set_snmp_metadata(self, update: SnmpMetadataUpdate) -> OperationResult[SnmpInfo]:
        """Set SNMP metadata with preserved service settings and full read-back."""

        if update.contact is not None:
            validate_snmp_metadata(update.contact, "contact")
        if update.location is not None:
            validate_snmp_metadata(update.location, "location")

        with self._transport_factory(self._connection) as transport:
            system_payload = transport.request(
                "GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            if identity_from_system(parse_payload(system_payload)) != self._identity:
                raise ProtocolError("CSS106 identity changed after device probing")

            before_payload = transport.request(
                "GET", "/snmp.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before_data = parse_payload(before_payload)
            before_info = snmp_from_payload(before_data)
            content, expected_state = encode_snmp_metadata_update(before_data, update)
            desired_contact = before_info.contact if update.contact is None else update.contact
            desired_location = before_info.location if update.location is None else update.location
            if before_info.contact == desired_contact and before_info.location == desired_location:
                return OperationResult[SnmpInfo](changed=False, value=before_info)

            transport.request(
                "POST",
                "/snmp.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request(
                "GET", "/snmp.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )

        after_data = parse_payload(after_payload)
        if snmp_write_state_from_payload(after_data) != expected_state:
            after_info = snmp_from_payload(after_data)
            if (
                after_info.enabled != before_info.enabled
                or after_info.community != before_info.community
                or after_info.contact != desired_contact
                or after_info.location != desired_location
            ):
                raise ProtocolError("CSS106 SNMP metadata write failed read-back verification")
        return OperationResult[SnmpInfo](changed=True, value=snmp_from_payload(after_data))

    def replace_static_hosts(
        self,
        hosts: tuple[HostEntry, ...],
        *,
        expected_current: tuple[HostEntry, ...],
    ) -> OperationResult[tuple[HostEntry, ...]]:
        """Replace all static hosts with identity, no-op, and read-back guards."""

        content = encode_static_hosts(hosts, self._identity)
        with self._transport_factory(self._connection) as transport:
            self._verify_identity(transport)
            before_payload = transport.request(
                "GET", "/host.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before = static_hosts_from_payload(parse_table_payload(before_payload), self._identity)
            if before != expected_current:
                raise InvalidOperationError(
                    "CSS106 static host table changed since the expected baseline"
                )
            if before == hosts:
                return OperationResult[tuple[HostEntry, ...]](changed=False, value=before)

            transport.request(
                "POST",
                "/host.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request(
                "GET", "/host.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )

        after = static_hosts_from_payload(parse_table_payload(after_payload), self._identity)
        if after != hosts:
            raise ProtocolError("CSS106 static-host write failed full-table read-back verification")
        return OperationResult[tuple[HostEntry, ...]](changed=True, value=after)

    def replace_acl_rules(
        self,
        rules: tuple[AclRule, ...],
        *,
        expected_current: tuple[AclRule, ...],
    ) -> OperationResult[tuple[AclRule, ...]]:
        """Replace all ACL rules with identity, no-op, and read-back guards."""

        content = encode_acl_rules(rules, self._identity)
        with self._transport_factory(self._connection) as transport:
            self._verify_identity(transport)
            before_payload = transport.request(
                "GET", "/acl.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before = acl_rules_from_payload(parse_table_payload(before_payload), self._identity)
            if before != expected_current:
                raise InvalidOperationError("CSS106 ACL table changed since the expected baseline")
            if before == rules:
                return OperationResult[tuple[AclRule, ...]](changed=False, value=before)

            transport.request(
                "POST",
                "/acl.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request("GET", "/acl.b", max_response_bytes=MAX_PAYLOAD_BYTES)

        after = acl_rules_from_payload(parse_table_payload(after_payload), self._identity)
        if after != rules:
            raise ProtocolError("CSS106 ACL write failed full-table read-back verification")
        return OperationResult[tuple[AclRule, ...]](changed=True, value=after)

    def _verify_identity(self, transport: HttpTransport) -> None:
        system_payload = transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        if identity_from_system(parse_payload(system_payload)) != self._identity:
            raise ProtocolError("CSS106 identity changed after device probing")


def _system_configuration(info: SystemInfo) -> tuple[object, ...]:
    return (
        info.static_ip,
        info.mac_address,
        info.serial_number,
        info.management,
        info.independent_vlan_lookup,
        info.igmp,
        info.discovery_protocol_port_numbers,
    )


def _changes_active_port_connectivity(update: PortConfigurationUpdate, before: PortInfo) -> bool:
    if update.enabled is False and before.enabled:
        return True
    if update.negotiation == "auto":
        return not before.auto_negotiation
    if update.negotiation is None:
        return False
    return (
        before.auto_negotiation
        or before.configured_speed_bps != update.negotiation.speed_bps
        or before.configured_full_duplex != (update.negotiation.duplex == "full")
    )
