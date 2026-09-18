"""CSS106 adapter for guarded reads and writes."""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import IPv4Address, ip_address
from time import sleep
from urllib.parse import urlsplit, urlunsplit

from pydantic import AnyHttpUrl, SecretStr, TypeAdapter, ValidationError
from swos_core.errors import (
    AuthenticationError,
    HttpStatusError,
    InvalidOperationError,
    ManagementStateUncertainError,
    PasswordUpdateRejectedError,
    ProtocolError,
    SwOSError,
    TransportError,
)
from swos_core.models import (
    AclRule,
    AddressMode,
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PasswordUpdate,
    PortConfigurationUpdate,
    PortInfo,
    PortNameUpdate,
    PortStatistics,
    PortVlanInfo,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpInfo,
    RstpPortEnableUpdate,
    SafetyWarning,
    SfpInfo,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    SystemInfo,
    VlanInfo,
)
from swos_core.transport import HttpTransport

from swos_device_css106.protocol import (
    MAX_PAYLOAD_BYTES,
    ForwardingWriteState,
    SwOSValue,
    SystemConfigurationWriteState,
    acl_rules_from_payload,
    dynamic_hosts_from_payload,
    encode_acl_rules,
    encode_forwarding_matrix_update,
    encode_forwarding_mirroring_update,
    encode_forwarding_port_policy_update,
    encode_password_update,
    encode_port_configuration_update,
    encode_port_name_update,
    encode_port_vlan_policy_update,
    encode_rstp_bridge_update,
    encode_rstp_port_enable_update,
    encode_snmp_metadata_update,
    encode_static_hosts,
    encode_system_configuration_update,
    encode_vlans,
    forwarding_from_payload,
    forwarding_write_state_from_payload,
    identity_from_system,
    igmp_groups_from_payload,
    link_write_state_from_payload,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlan_write_state_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    rstp_bridge_write_state_from_payload,
    rstp_enable_write_state_from_payload,
    rstp_from_payloads,
    sfp_from_payload,
    snmp_from_payload,
    snmp_write_state_from_payload,
    static_hosts_from_payload,
    system_configuration_write_state_from_payload,
    system_info_from_payload,
    validate_device_name,
    validate_password_update,
    validate_port_name,
    validate_snmp_metadata,
    vlan_table_write_state_from_payload,
    vlans_from_payload,
)

MANAGEMENT_READBACK_ATTEMPTS = 60
MANAGEMENT_READBACK_DELAY_SECONDS = 1.0
_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


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
                    "admin_password_write",
                    "acl_write",
                    "device_name_write",
                    "forwarding_matrix_write",
                    "forwarding_mirroring_write",
                    "forwarding_port_policy_write",
                    "port_configuration_write",
                    "port_name_write",
                    "rstp_bridge_write",
                    "rstp_port_enable_write",
                    "snmp_metadata_write",
                    "static_hosts_write",
                    "system_configuration_write",
                    "vlan_port_policy_write",
                    "vlan_table_write",
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

    def validate_port_name(self, update: PortNameUpdate) -> None:
        """Validate a port-name update without opening a transport."""

        validate_port_name(update.name)
        self._validate_writable_port(update.number)

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

    def validate_port_configuration(
        self,
        update: PortConfigurationUpdate,
        *,
        current: PortInfo,
    ) -> None:
        """Validate port configuration against a fresh normalized read."""

        self._validate_writable_port(update.number)
        if current.number != update.number:
            raise InvalidOperationError(
                f"Expected current port {update.number}, received port {current.number}"
            )
        if isinstance(update.negotiation, ForcedPortNegotiation) and (
            update.negotiation.speed_bps not in (10_000_000, 100_000_000)
        ):
            raise InvalidOperationError("CSS106 forced speed must be 10000000 or 100000000 bps")
        if current.link_up and _changes_active_port_connectivity(update, current):
            raise InvalidOperationError(
                f"Port {update.number} is link-up; active ports cannot be disabled or "
                "have negotiation changed"
            )

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        """Set the device name with a fresh identity check and complete system write."""

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
            content, expected_state = encode_system_configuration_update(
                before_data,
                self._identity,
                SystemConfigurationUpdate(name=update.name),
            )
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
        if (
            system_configuration_write_state_from_payload(after_data, self._identity)
            != expected_state
        ):
            raise ProtocolError("CSS106 device-name write failed read-back verification")
        return OperationResult[SystemInfo](
            changed=True,
            value=system_info_from_payload(after_data, reported_identity),
        )

    def validate_device_name(self, update: DeviceNameUpdate) -> None:
        """Validate a device-name update without opening a transport."""

        validate_device_name(update.name)

    def set_admin_password(self, update: PasswordUpdate) -> OperationResult[SystemInfo]:
        """Rotate credentials and verify identity using only the new password."""

        validate_password_update(update, self._connection.password)
        content = encode_password_update(update, self._connection.password)
        try:
            with self._transport_factory(self._connection) as transport:
                transport.request(
                    "POST",
                    "/!pwd.b",
                    content=content,
                    headers={"Content-Type": "text/plain"},
                    max_response_bytes=MAX_PAYLOAD_BYTES,
                )
        except HttpStatusError as exc:
            if exc.status_code == 405:
                raise PasswordUpdateRejectedError(
                    "The SwOS device rejected the current administrator password"
                ) from exc
            raise

        new_connection = self._connection.model_copy(
            update={
                "password": SecretStr(update.new_password.get_secret_value()),
            }
        )
        with self._transport_factory(new_connection) as transport:
            after_data = parse_payload(
                transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )
        reported_identity = identity_from_system(after_data)
        if reported_identity != self._identity:
            raise ProtocolError("CSS106 identity changed after administrator password update")
        self._connection = new_connection
        verified_info = system_info_from_payload(after_data, reported_identity)
        return OperationResult[SystemInfo](
            changed=True,
            value=verified_info,
            warnings=(
                SafetyWarning(
                    code="administrator_credentials_changed",
                    message=(
                        "Administrator credentials changed. Future connections must use the new "
                        "password; failed verification can indicate credential lockout and may "
                        "require a manual factory reset."
                    ),
                ),
            ),
        )

    def validate_admin_password(self, update: PasswordUpdate) -> None:
        """Validate current and desired credentials without opening a transport."""

        validate_password_update(update, self._connection.password)

    def set_system_configuration(
        self,
        update: SystemConfigurationUpdate,
        *,
        expected_current: SystemInfo,
        readback_url: str | None = None,
    ) -> OperationResult[SystemInfo]:
        """Set the complete system object with baseline and address guards."""

        self.validate_system_configuration(
            update,
            current=expected_current,
            readback_url=readback_url,
        )
        reconnect_connection: DeviceConnection | None = None
        desired: SystemConfigurationWriteState | None = None
        operation_warnings: tuple[SafetyWarning, ...] = ()
        post_error: SwOSError | None = None
        with self._transport_factory(self._connection) as transport:
            before_data = parse_payload(
                transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )
            reported_identity = identity_from_system(before_data)
            if reported_identity != self._identity:
                raise ProtocolError("CSS106 identity changed after device probing")
            before = system_info_from_payload(before_data, reported_identity)
            self.validate_system_configuration(
                update,
                current=before,
                readback_url=readback_url,
            )
            if _system_writable_configuration(before) != _system_writable_configuration(
                expected_current
            ):
                raise InvalidOperationError(
                    "CSS106 system configuration changed since the expected baseline"
                )
            if (
                before.serial_number != expected_current.serial_number
                or before.mac_address != expected_current.mac_address
            ):
                raise InvalidOperationError(
                    "CSS106 physical identity changed since the expected system baseline"
                )
            before_state = system_configuration_write_state_from_payload(
                before_data, self._identity
            )
            content, desired = encode_system_configuration_update(
                before_data, self._identity, update
            )
            if desired == before_state:
                return OperationResult[SystemInfo](changed=False, value=before)
            operation_warnings = _management_lockout_warnings(update, before)
            selected_url = _management_readback_url(
                update,
                before,
                self._connection,
                readback_url,
            )
            if selected_url is None:
                transport.request(
                    "POST",
                    "/sys.b",
                    content=content,
                    headers={"Content-Type": "text/plain"},
                    max_response_bytes=MAX_PAYLOAD_BYTES,
                )
                after_data = parse_payload(
                    transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
                )
            else:
                reconnect_connection = self._connection.model_copy(update={"url": selected_url})
                try:
                    transport.request(
                        "POST",
                        "/sys.b",
                        content=content,
                        headers={"Content-Type": "text/plain"},
                        max_response_bytes=MAX_PAYLOAD_BYTES,
                    )
                except (AuthenticationError, HttpStatusError, ProtocolError):
                    raise
                except TransportError as exc:
                    post_error = exc

        if reconnect_connection is not None:
            assert desired is not None
            return self._poll_system_configuration_readback(
                reconnect_connection,
                desired,
                operation_warnings,
                original_serial_number=expected_current.serial_number,
                original_mac_address=expected_current.mac_address,
                initial_error=post_error,
            )
        reported_identity = identity_from_system(after_data)
        if reported_identity != self._identity:
            raise ProtocolError("CSS106 identity changed after system-configuration write")
        if system_configuration_write_state_from_payload(after_data, self._identity) != desired:
            raise ProtocolError(
                "CSS106 system-configuration write failed complete-object read-back verification"
            )
        return OperationResult[SystemInfo](
            changed=True,
            value=system_info_from_payload(after_data, reported_identity),
            warnings=operation_warnings,
        )

    def validate_system_configuration(
        self,
        update: SystemConfigurationUpdate,
        *,
        current: SystemInfo,
        readback_url: str | None = None,
    ) -> None:
        """Validate system changes against normalized state without transport access."""

        if current.identity != self._identity:
            raise InvalidOperationError(
                "Current system identity does not match the connected device"
            )
        management = current.management
        igmp = current.igmp
        if management is None or igmp is None or current.independent_vlan_lookup is None:
            raise InvalidOperationError("Current system configuration is incomplete")
        desired_mode, desired_static_ip, _ = _desired_management_state(update, current)
        if desired_static_ip is not None:
            _validate_static_management_ip(desired_static_ip)
        _management_readback_url(update, current, self._connection, readback_url)
        if update.name is not None:
            validate_device_name(update.name)
        for ports, label in (
            (update.allowed_port_numbers, "management allowed"),
            (update.igmp_fast_leave_port_numbers, "IGMP fast-leave"),
            (update.discovery_protocol_port_numbers, "discovery protocol"),
        ):
            if ports is not None:
                self._validate_system_mask_ports(ports, label)

        desired_allowed_ports = (
            management.allowed_port_numbers
            if update.allowed_port_numbers is None
            else update.allowed_port_numbers
        )
        if 6 not in desired_allowed_ports:
            raise InvalidOperationError("CSS106 management allowed ports must include port 6")
        if update.allowed_port_numbers is not None:
            if (6 in update.allowed_port_numbers) != (6 in management.allowed_port_numbers):
                raise InvalidOperationError("CSS106 system writes cannot change port 6 mask state")
        for ports, existing in (
            (update.igmp_fast_leave_port_numbers, igmp.fast_leave_port_numbers),
            (update.discovery_protocol_port_numbers, current.discovery_protocol_port_numbers),
        ):
            if ports is not None and (6 in ports) != (6 in existing):
                raise InvalidOperationError("CSS106 system writes cannot change port 6 mask state")

        if desired_mode is AddressMode.STATIC and desired_static_ip is None:
            raise InvalidOperationError(
                "CSS106 static address mode requires a configured static IP"
            )
        if desired_mode is AddressMode.DHCP_ONLY and desired_static_ip != current.static_ip:
            raise InvalidOperationError(
                "CSS106 static-IP staging is allowed only in DHCP-with-fallback mode"
            )

    def _poll_system_configuration_readback(
        self,
        connection: DeviceConnection,
        desired: SystemConfigurationWriteState,
        warnings: tuple[SafetyWarning, ...],
        *,
        original_serial_number: str | None,
        original_mac_address: str | None,
        initial_error: SwOSError | None,
    ) -> OperationResult[SystemInfo]:
        last_error = initial_error
        for attempt in range(MANAGEMENT_READBACK_ATTEMPTS):
            try:
                with self._transport_factory(connection) as transport:
                    after_data = parse_payload(
                        transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
                    )
                reported_identity = identity_from_system(after_data)
                if reported_identity != self._identity:
                    raise ProtocolError("CSS106 identity changed after management-path reconnect")
                if (
                    system_configuration_write_state_from_payload(after_data, self._identity)
                    != desired
                ):
                    raise ProtocolError(
                        "CSS106 management-path write failed complete-object read-back verification"
                    )
                verified_info = system_info_from_payload(after_data, reported_identity)
                if (
                    verified_info.serial_number != original_serial_number
                    or verified_info.mac_address != original_mac_address
                ):
                    raise ProtocolError(
                        "CSS106 physical identity changed after management-path reconnect"
                    )
            except SwOSError as exc:
                last_error = exc
                if attempt + 1 < MANAGEMENT_READBACK_ATTEMPTS:
                    sleep(MANAGEMENT_READBACK_DELAY_SECONDS)
                continue

            self._connection = connection
            return OperationResult[SystemInfo](
                changed=True,
                value=verified_info,
                warnings=warnings,
            )

        raise ManagementStateUncertainError(
            "The CSS106 management write was sent, but the selected management URL did not "
            "return the exact device and complete target state. The device state is uncertain; "
            "do not retry the write, and perform a manual reset if neither management address "
            "is reachable."
        ) from last_error

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

    def validate_snmp_metadata(self, update: SnmpMetadataUpdate) -> None:
        """Validate SNMP metadata without opening a transport."""

        if update.contact is not None:
            validate_snmp_metadata(update.contact, "contact")
        if update.location is not None:
            validate_snmp_metadata(update.location, "location")

    def set_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set one RSTP enable bit with baseline, identity, and port-6 guards."""

        with self._transport_factory(self._connection) as transport:
            before, _, before_rstp_data = self._read_rstp(transport)
            if _rstp_configuration(before) != _rstp_configuration(expected_current):
                raise InvalidOperationError(
                    "CSS106 RSTP configuration changed since the expected baseline"
                )
            before_state = rstp_enable_write_state_from_payload(before_rstp_data, self._identity)
            content, desired = encode_rstp_port_enable_update(
                before_rstp_data, self._identity, update
            )
            if desired == before_state:
                return OperationResult[RstpInfo](changed=False, value=before)

            transport.request(
                "POST",
                "/rstp.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after, _, after_rstp_data = self._read_rstp(transport)

        if rstp_enable_write_state_from_payload(after_rstp_data, self._identity) != desired:
            raise ProtocolError("CSS106 RSTP enable write failed read-back verification")
        return OperationResult[RstpInfo](changed=True, value=after)

    def validate_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        current: RstpInfo,
    ) -> None:
        """Validate an RSTP update against a fresh normalized read."""

        self._validate_writable_port(update.number)
        self._require_numbered(current.ports, update.number, "RSTP port")

    def set_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set the complete bridge group with baseline and identity guards."""

        with self._transport_factory(self._connection) as transport:
            before, before_system_data, _ = self._read_rstp(transport)
            if _rstp_configuration(before) != _rstp_configuration(expected_current):
                raise InvalidOperationError(
                    "CSS106 RSTP configuration changed since the expected baseline"
                )
            before_state = rstp_bridge_write_state_from_payload(before_system_data)
            content, desired = encode_rstp_bridge_update(before_system_data, update)
            if desired == before_state:
                return OperationResult[RstpInfo](changed=False, value=before)

            transport.request(
                "POST",
                "/sys.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after, after_system_data, _ = self._read_rstp(transport)

        if rstp_bridge_write_state_from_payload(after_system_data) != desired:
            raise ProtocolError("CSS106 RSTP bridge write failed read-back verification")
        return OperationResult[RstpInfo](changed=True, value=after)

    def validate_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        current: RstpInfo,
    ) -> None:
        """Validate bridge configuration against a fresh normalized read."""

        del update
        if not current.ports:
            raise InvalidOperationError("Current CSS106 RSTP configuration is incomplete")

    def set_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set lock or egress-rate policy using one complete forwarding POST."""

        return self._set_forwarding(
            expected_current,
            lambda data: encode_forwarding_port_policy_update(data, self._identity, update),
        )

    def validate_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        current: ForwardingInfo,
    ) -> None:
        """Validate forwarding policy against a fresh normalized read."""

        self._validate_writable_port(update.number)
        self._require_numbered(current.ports, update.number, "forwarding port")
        management = next((port for port in current.ports if port.number == 6), None)
        if (
            management is not None and (management.mirror_ingress or management.mirror_egress)
        ) or current.mirror_target_port == 6:
            raise InvalidOperationError(
                "CSS106 forwarding writes require management port 6 to be absent from mirroring"
            )

    def set_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set one forwarding row without changing relationships involving port 6."""

        return self._set_forwarding(
            expected_current,
            lambda data: encode_forwarding_matrix_update(data, self._identity, update),
        )

    def validate_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        current: ForwardingInfo,
    ) -> None:
        """Validate one forwarding row against a fresh normalized read."""

        self._validate_forwarding_update_state(current)
        self._validate_writable_port(update.number)
        port = next(
            (item for item in current.ports if item.number == update.number),
            None,
        )
        if port is None:
            raise InvalidOperationError(
                f"forwarding port {update.number} was not returned by the device"
            )
        known_ports = {item.number for item in current.ports}
        if tuple(sorted(update.destination_port_numbers)) != update.destination_port_numbers:
            raise InvalidOperationError("Forwarding destination ports must be in ascending order")
        if any(number not in known_ports for number in update.destination_port_numbers):
            raise InvalidOperationError("Forwarding destinations must reference declared ports")
        if (6 in update.destination_port_numbers) != (6 in port.destination_port_numbers):
            raise InvalidOperationError(
                "CSS106 forwarding writes cannot alter a destination relationship involving port 6"
            )

    def set_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set mirroring while rejecting management port 6 as source or target."""

        return self._set_forwarding(
            expected_current,
            lambda data: encode_forwarding_mirroring_update(data, self._identity, update),
        )

    def validate_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        current: ForwardingInfo,
    ) -> None:
        """Validate mirroring against a fresh normalized read."""

        self._validate_forwarding_update_state(current)
        self._validate_writable_port(update.source_port_number)
        self._require_numbered(current.ports, update.source_port_number, "forwarding port")
        if update.mirror_target_port not in (None, "none"):
            assert isinstance(update.mirror_target_port, int)
            self._validate_writable_port(update.mirror_target_port)

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

    def validate_static_hosts(self, hosts: tuple[HostEntry, ...]) -> None:
        """Validate a complete static-host table without opening a transport."""

        encode_static_hosts(hosts, self._identity)

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

    def validate_acl_rules(self, rules: tuple[AclRule, ...]) -> None:
        """Validate a complete ACL table without opening a transport."""

        encode_acl_rules(rules, self._identity)

    def set_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        expected_current: tuple[PortVlanInfo, ...],
    ) -> OperationResult[tuple[PortVlanInfo, ...]]:
        """Set one Ethernet port's complete VLAN policy with baseline guards."""

        with self._transport_factory(self._connection) as transport:
            self._verify_identity(transport)
            before_data = parse_payload(
                transport.request("GET", "/fwd.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )
            before = port_vlans_from_forwarding_payload(before_data, self._identity)
            if before != expected_current:
                raise InvalidOperationError(
                    "CSS106 port VLAN policy changed since the expected baseline"
                )
            before_state = port_vlan_write_state_from_payload(before_data, self._identity)
            content, desired = encode_port_vlan_policy_update(before_data, self._identity, update)
            if desired == before_state:
                return OperationResult[tuple[PortVlanInfo, ...]](changed=False, value=before)

            transport.request(
                "POST",
                "/fwd.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_data = parse_payload(
                transport.request("GET", "/fwd.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )

        if port_vlan_write_state_from_payload(after_data, self._identity) != desired:
            raise ProtocolError(
                "CSS106 port VLAN write failed complete-group read-back verification"
            )
        return OperationResult[tuple[PortVlanInfo, ...]](
            changed=True,
            value=port_vlans_from_forwarding_payload(after_data, self._identity),
        )

    def validate_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        current: tuple[PortVlanInfo, ...],
    ) -> None:
        """Validate port VLAN policy against a fresh normalized read."""

        self._validate_writable_port(update.number)
        self._require_numbered(current, update.number, "VLAN port")

    def replace_vlans(
        self,
        vlans: tuple[VlanInfo, ...],
        *,
        expected_current: tuple[VlanInfo, ...],
    ) -> OperationResult[tuple[VlanInfo, ...]]:
        """Replace the full VLAN table with baseline and port-6 membership guards."""

        content = encode_vlans(vlans, expected_current, self._identity)
        desired_state = vlan_table_write_state_from_payload(
            parse_table_payload(content), self._identity
        )
        with self._transport_factory(self._connection) as transport:
            self._verify_identity(transport)
            before_payload = transport.request(
                "GET", "/vlan.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )
            before = vlans_from_payload(parse_table_payload(before_payload), self._identity)
            if before != expected_current:
                raise InvalidOperationError("CSS106 VLAN table changed since the expected baseline")
            if before == vlans:
                return OperationResult[tuple[VlanInfo, ...]](changed=False, value=before)

            transport.request(
                "POST",
                "/vlan.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_payload = transport.request(
                "GET", "/vlan.b", max_response_bytes=MAX_PAYLOAD_BYTES
            )

        after_rows = parse_table_payload(after_payload)
        after = vlans_from_payload(after_rows, self._identity)
        if vlan_table_write_state_from_payload(after_rows, self._identity) != desired_state:
            raise ProtocolError("CSS106 VLAN write failed full-table read-back verification")
        return OperationResult[tuple[VlanInfo, ...]](changed=True, value=after)

    def validate_vlans(
        self,
        vlans: tuple[VlanInfo, ...],
        *,
        current: tuple[VlanInfo, ...],
    ) -> None:
        """Validate a complete VLAN table without opening a transport."""

        encode_vlans(vlans, current, self._identity)

    def _verify_identity(self, transport: HttpTransport) -> None:
        system_payload = transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        if identity_from_system(parse_payload(system_payload)) != self._identity:
            raise ProtocolError("CSS106 identity changed after device probing")

    def _validate_writable_port(self, number: int) -> None:
        if number == 6:
            raise InvalidOperationError("Port 6 is the SFP management port and cannot be modified")
        if number < 1 or number > 5:
            raise InvalidOperationError(
                f"Port {number} does not exist on {self._identity.product_code}"
            )

    @staticmethod
    def _validate_forwarding_update_state(current: ForwardingInfo) -> None:
        management = next((port for port in current.ports if port.number == 6), None)
        if (
            management is not None and (management.mirror_ingress or management.mirror_egress)
        ) or current.mirror_target_port == 6:
            raise InvalidOperationError(
                "CSS106 forwarding writes require management port 6 to be absent from mirroring"
            )

    @staticmethod
    def _validate_system_mask_ports(port_numbers: tuple[int, ...], label: str) -> None:
        if any(number > 6 for number in port_numbers):
            raise InvalidOperationError(f"CSS106 {label} ports must be between 1 and 6")
        if port_numbers != tuple(sorted(port_numbers)):
            raise InvalidOperationError(f"CSS106 {label} ports must be in ascending order")

    @staticmethod
    def _require_numbered(items: tuple[object, ...], number: int, label: str) -> None:
        if not any(getattr(item, "number", None) == number for item in items):
            raise InvalidOperationError(f"{label} {number} was not returned by the device")

    def _read_rstp(
        self, transport: HttpTransport
    ) -> tuple[RstpInfo, dict[str, SwOSValue], dict[str, SwOSValue]]:
        system_data = parse_payload(
            transport.request("GET", "/sys.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        )
        if identity_from_system(system_data) != self._identity:
            raise ProtocolError("CSS106 identity changed after device probing")
        rstp_data = parse_payload(
            transport.request("GET", "/rstp.b", max_response_bytes=MAX_PAYLOAD_BYTES)
        )
        return (
            rstp_from_payloads(rstp_data, system_data, self._identity),
            system_data,
            rstp_data,
        )

    def _set_forwarding(
        self,
        expected_current: ForwardingInfo,
        encode: Callable[[dict[str, SwOSValue]], tuple[bytes, ForwardingWriteState]],
    ) -> OperationResult[ForwardingInfo]:
        with self._transport_factory(self._connection) as transport:
            self._verify_identity(transport)
            before_data = parse_payload(
                transport.request("GET", "/fwd.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )
            before = forwarding_from_payload(before_data, self._identity)
            if before != expected_current:
                raise InvalidOperationError(
                    "CSS106 forwarding configuration changed since the expected baseline"
                )
            before_state = forwarding_write_state_from_payload(before_data, self._identity)
            content, desired = encode(before_data)
            if desired == before_state:
                return OperationResult[ForwardingInfo](changed=False, value=before)

            transport.request(
                "POST",
                "/fwd.b",
                content=content,
                headers={"Content-Type": "text/plain"},
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
            after_data = parse_payload(
                transport.request("GET", "/fwd.b", max_response_bytes=MAX_PAYLOAD_BYTES)
            )

        if forwarding_write_state_from_payload(after_data, self._identity) != desired:
            raise ProtocolError(
                "CSS106 forwarding write failed complete-group read-back verification"
            )
        return OperationResult[ForwardingInfo](
            changed=True,
            value=forwarding_from_payload(after_data, self._identity),
        )


def _system_writable_configuration(info: SystemInfo) -> tuple[object, ...]:
    management = info.management
    igmp = info.igmp
    return (
        info.name,
        info.static_ip,
        None if management is None else management.address_mode,
        None if management is None else management.admin_mac_address,
        None if management is None else management.allow_from,
        None if management is None else management.allow_prefix_length,
        None if management is None else management.allowed_port_numbers,
        None if management is None else management.allowed_vlan_id,
        info.independent_vlan_lookup,
        None if igmp is None else igmp.enabled,
        None if igmp is None else igmp.querier_configured,
        None if igmp is None else igmp.fast_leave_port_numbers,
        None if igmp is None else igmp.version,
        info.discovery_protocol_port_numbers,
    )


def _desired_management_state(
    update: SystemConfigurationUpdate,
    current: SystemInfo,
) -> tuple[AddressMode, str | None, int | None]:
    management = current.management
    if management is None:
        raise InvalidOperationError("Current system management configuration is incomplete")
    desired_mode = update.address_mode or management.address_mode
    desired_static_ip = (
        current.static_ip
        if update.static_ip is None
        else None
        if update.static_ip == "unset"
        else update.static_ip
    )
    desired_vlan = (
        management.allowed_vlan_id
        if update.allowed_vlan_id is None
        else None
        if update.allowed_vlan_id == "unset"
        else update.allowed_vlan_id
    )
    return desired_mode, desired_static_ip, desired_vlan


def _validate_static_management_ip(value: str) -> None:
    try:
        address = IPv4Address(value)
    except ValueError as exc:
        raise InvalidOperationError(
            "CSS106 static management IP must be a usable unicast IPv4 address"
        ) from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_reserved
        or address == IPv4Address("255.255.255.255")
    ):
        raise InvalidOperationError(
            "CSS106 static management IP must be a usable unicast IPv4 address"
        )


def _management_readback_url(
    update: SystemConfigurationUpdate,
    current: SystemInfo,
    connection: DeviceConnection,
    readback_url: str | None,
) -> AnyHttpUrl | None:
    explicit_url = (
        None
        if readback_url is None
        else _validate_readback_url(readback_url, original_url=connection.url)
    )
    management = current.management
    if management is None:
        raise InvalidOperationError("Current system management configuration is incomplete")
    desired_mode, desired_static_ip, desired_vlan = _desired_management_state(update, current)
    desired_admin_mac = management.admin_mac_address
    if update.admin_mac_address is not None:
        desired_admin_mac = (
            None if update.admin_mac_address == "unset" else update.admin_mac_address
        )
    mode_changed = desired_mode is not management.address_mode
    static_ip_changed = desired_static_ip != current.static_ip
    current_uses_static_ip = management.address_mode is AddressMode.STATIC or (
        management.address_mode is AddressMode.DHCP_WITH_FALLBACK
        and current.static_ip is not None
        and current.current_ip == current.static_ip
    )
    active_static_ip_changed = static_ip_changed and current_uses_static_ip
    vlan_changed = desired_vlan != management.allowed_vlan_id
    admin_mac_changed = desired_admin_mac != management.admin_mac_address
    management_path_changed = mode_changed or active_static_ip_changed or vlan_changed
    if not (management_path_changed or admin_mac_changed):
        return None
    deterministic_static_target = desired_mode is AddressMode.STATIC or (
        active_static_ip_changed and desired_static_ip is not None
    )
    if deterministic_static_target:
        if desired_static_ip is None:
            raise InvalidOperationError(
                "CSS106 static address mode requires a configured static IP"
            )
        derived_url = _replace_url_host(connection.url, desired_static_ip)
        if explicit_url is not None and explicit_url != derived_url:
            raise InvalidOperationError(
                "readback_url must equal the deterministic URL derived from the desired static IP"
            )
        return derived_url
    if explicit_url is not None and management_path_changed:
        return explicit_url
    if active_static_ip_changed:
        raise InvalidOperationError(
            "CSS106 removal of an active DHCP-fallback static IP requires an explicit readback_url"
        )
    if mode_changed and not _dhcp_mode_keeps_current_url(current, connection.url):
        raise InvalidOperationError(
            "CSS106 DHCP address-mode changes require an explicit readback_url because the "
            "resulting lease address cannot be inferred safely"
        )
    return connection.url


def _validate_readback_url(value: str, *, original_url: AnyHttpUrl) -> AnyHttpUrl:
    if "\\" in value or "%5c" in value.casefold():
        raise InvalidOperationError("readback_url must not contain a backslash")
    try:
        canonical_url = _HTTP_URL_ADAPTER.validate_python(value)
        canonical_value = str(canonical_url)
        parsed = urlsplit(canonical_value)
        parsed_port = parsed.port
    except (ValidationError, ValueError) as exc:
        raise InvalidOperationError(
            "readback_url must be a valid HTTP or HTTPS device base URL"
        ) from exc
    if parsed.scheme.casefold() not in {"http", "https"} or parsed.hostname is None:
        raise InvalidOperationError("readback_url must be a bare HTTP or HTTPS device base URL")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidOperationError("readback_url must not contain user information")
    if (
        parsed.path not in {"", "/"}
        or canonical_url.query is not None
        or canonical_url.fragment is not None
    ):
        raise InvalidOperationError("readback_url must not contain a path, query, or fragment")
    accepted_values = {canonical_value, canonical_value.removesuffix("/")}
    if value not in accepted_values:
        raise InvalidOperationError("readback_url must use its canonical bare URL spelling")

    original = urlsplit(str(original_url))
    if parsed.scheme.casefold() != original.scheme.casefold():
        raise InvalidOperationError(
            "readback_url must use the same scheme as the current device URL"
        )
    if _effective_port(parsed.scheme, parsed_port) != _effective_port(
        original.scheme, original.port
    ):
        raise InvalidOperationError(
            "readback_url must use the same explicit or effective port as the current device URL"
        )
    return canonical_url


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme.casefold() == "https" else 80


def _replace_url_host(url: AnyHttpUrl, host: str) -> AnyHttpUrl:
    parsed = urlsplit(str(url))
    bracketed_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = bracketed_host
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    replaced = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    return _HTTP_URL_ADAPTER.validate_python(replaced)


def _dhcp_mode_keeps_current_url(current: SystemInfo, url: AnyHttpUrl) -> bool:
    management = current.management
    if management is None or current.current_ip is None:
        return False
    if management.address_mode is AddressMode.STATIC:
        return False
    if (
        management.address_mode is AddressMode.DHCP_WITH_FALLBACK
        and current.current_ip == current.static_ip
    ):
        return False
    host = urlsplit(str(url)).hostname
    if host is None:
        return False
    try:
        return ip_address(host) == ip_address(current.current_ip)
    except ValueError:
        return host.casefold() == current.current_ip.casefold()


def _management_lockout_warnings(
    update: SystemConfigurationUpdate, before: SystemInfo
) -> tuple[SafetyWarning, ...]:
    management = before.management
    if management is None:
        return ()
    changes: list[str] = []
    desired_admin_mac = (
        management.admin_mac_address
        if update.admin_mac_address is None
        else None
        if update.admin_mac_address == "unset"
        else update.admin_mac_address
    )
    if desired_admin_mac != management.admin_mac_address:
        changes.append(
            f"admin MAC {management.admin_mac_address or 'unset'} -> {desired_admin_mac or 'unset'}"
        )

    desired_allow_from = (
        management.allow_from
        if update.allow_from is None
        else None
        if update.allow_from == "unset"
        else update.allow_from
    )
    desired_prefix = (
        management.allow_prefix_length
        if update.allow_prefix_length is None
        else update.allow_prefix_length
    )
    before_source = _management_source(management.allow_from, management.allow_prefix_length)
    desired_source = _management_source(desired_allow_from, desired_prefix)
    if desired_source != before_source:
        changes.append(f"allow from {before_source} -> {desired_source}")

    desired_ports = (
        management.allowed_port_numbers
        if update.allowed_port_numbers is None
        else update.allowed_port_numbers
    )
    if desired_ports != management.allowed_port_numbers:
        before_ports = ",".join(str(number) for number in management.allowed_port_numbers)
        after_ports = ",".join(str(number) for number in desired_ports)
        changes.append(f"allowed ports {before_ports} -> {after_ports}")

    desired_mode, desired_static_ip, desired_vlan = _desired_management_state(update, before)
    if desired_mode is not management.address_mode:
        changes.append(f"address mode {management.address_mode.value} -> {desired_mode.value}")
    current_uses_static_ip = management.address_mode is AddressMode.STATIC or (
        management.address_mode is AddressMode.DHCP_WITH_FALLBACK
        and before.static_ip is not None
        and before.current_ip == before.static_ip
    )
    if desired_static_ip != before.static_ip and (
        current_uses_static_ip or desired_mode is AddressMode.STATIC
    ):
        changes.append(
            f"active static IP {before.static_ip or 'unset'} -> {desired_static_ip or 'unset'}"
        )
    if desired_vlan != management.allowed_vlan_id:
        changes.append(
            f"management VLAN {management.allowed_vlan_id or 'unset'} -> {desired_vlan or 'unset'}"
        )

    if not changes:
        return ()
    return (
        SafetyWarning(
            code="management_lockout_risk",
            message=(
                f"Management access changed ({'; '.join(changes)}). This explicitly authorized "
                "write can lock out the caller. Selected-URL readback is attempted, but "
                "connectivity loss leaves the outcome uncertain and may require a manual factory "
                "reset."
            ),
        ),
    )


def _management_source(address: str | None, prefix_length: int) -> str:
    return "any" if address is None else f"{address}/{prefix_length}"


def _rstp_configuration(info: RstpInfo) -> tuple[object, ...]:
    return (
        info.bridge_priority,
        info.cost_mode,
        info.forward_reserved_multicast,
        tuple(
            (
                port.number,
                port.enabled,
                port.protocol,
                port.configured_path_cost,
                port.point_to_point,
                port.edge,
            )
            for port in info.ports
        ),
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
