"""Ansible-independent execution layer built only on the public core API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol, TypeVar, cast

from swos_core import (
    DeviceConnection,
    DeviceNameUpdate,
    FirmwareSafetyPolicy,
    ForcedPortNegotiation,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    PluginRegistry,
    PortConfigurationUpdate,
    PortNameUpdate,
    PortVlanPolicyUpdate,
    RstpPortEnableUpdate,
    SafetyWarning,
    SnmpMetadataUpdate,
    SwOSDevice,
    UnsupportedFeatureError,
    VlanEgressMode,
    VlanMode,
    VlanReceiveMode,
)

JsonObject = dict[str, Any]
Params = Mapping[str, Any]
MAX_DEVICE_NAME_BYTES = 16
MAX_PORT_NAME_BYTES = 16
MAX_SNMP_METADATA_BYTES = 64
MAX_STATIC_HOSTS = 2048
FACT_SUBSETS = frozenset(
    {
        "all",
        "system",
        "ports",
        "port_statistics",
        "hosts",
        "rstp",
        "snmp",
        "sfp",
        "forwarding",
        "igmp_groups",
        "acl_rules",
        "port_vlans",
        "vlans",
    }
)


class _Serializable(Protocol):
    def model_dump(self, *, mode: Literal["json"]) -> dict[str, Any]: ...


class _Numbered(Protocol):
    number: int


Numbered = TypeVar("Numbered", bound=_Numbered)

WRITE_CAPABILITIES = {
    "device_name": "device_name_write",
    "port_name": "port_name_write",
    "port_configuration": "port_configuration_write",
    "snmp_metadata": "snmp_metadata_write",
    "static_hosts": "static_hosts_write",
    "rstp_port": "rstp_port_enable_write",
    "forwarding_port_policy": "forwarding_port_policy_write",
    "vlan_port_policy": "vlan_port_policy_write",
}


def execute(
    operation: str,
    params: Params,
    *,
    check_mode: bool = False,
    device: SwOSDevice | None = None,
) -> JsonObject:
    """Execute one collection operation, optionally against an injected facade."""

    _validate_operation_params(operation, params)
    if device is None:
        device, authorization_warnings = _connect(params, write=operation != "facts")
    else:
        authorization_warnings = device.warnings

    if operation == "facts":
        return _facts(device, params, authorization_warnings)
    capability = WRITE_CAPABILITIES.get(operation)
    if capability is not None and not device.capabilities.supports(capability):
        raise UnsupportedFeatureError(capability)
    if operation == "device_name":
        return _device_name(device, params, check_mode, authorization_warnings)
    if operation == "port_name":
        return _port_name(device, params, check_mode, authorization_warnings)
    if operation == "port_configuration":
        return _port_configuration(device, params, check_mode, authorization_warnings)
    if operation == "snmp_metadata":
        return _snmp_metadata(device, params, check_mode, authorization_warnings)
    if operation == "static_hosts":
        return _static_hosts(device, params, check_mode, authorization_warnings)
    if operation == "rstp_port":
        return _rstp_port(device, params, check_mode, authorization_warnings)
    if operation == "forwarding_port_policy":
        return _forwarding_port_policy(device, params, check_mode, authorization_warnings)
    if operation == "vlan_port_policy":
        return _vlan_port_policy(device, params, check_mode, authorization_warnings)
    raise ValueError(f"Unknown swos-ansible operation {operation!r}")


def _connect(params: Params, *, write: bool) -> tuple[SwOSDevice, tuple[SafetyWarning, ...]]:
    connection = DeviceConnection.model_validate(
        {
            "url": params["url"],
            "username": params.get("username", "admin"),
            "password": params.get("password", ""),
            "timeout": params.get("timeout", 10.0),
            "verify_tls": params.get("validate_certs", True),
        }
    )
    policy = FirmwareSafetyPolicy(
        allow_untested_firmware=bool(params.get("allow_untested_firmware", False)),
        allow_untested_firmware_writes=bool(params.get("allow_untested_firmware_writes", False)),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    resolution = registry.resolve(identity, policy, write=write)
    return registry.connect(identity, connection, policy), resolution.warnings


def _facts(
    device: SwOSDevice,
    params: Params,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    requested = cast(list[str], params.get("gather_subset", ["all"]))
    all_subsets = (
        "system",
        "ports",
        "port_statistics",
        "hosts",
        "rstp",
        "snmp",
        "sfp",
        "forwarding",
        "igmp_groups",
        "acl_rules",
        "port_vlans",
        "vlans",
    )
    subsets = all_subsets if "all" in requested else tuple(dict.fromkeys(requested))
    facts: JsonObject = {
        "identity": _dump(device.identity),
        "capabilities": sorted(device.capabilities.features),
    }
    for subset in subsets:
        facts[subset] = _read_subset(device, subset)
    result: JsonObject = {"changed": False, "ansible_facts": {"swos": facts}}
    return _with_warnings(result, warnings)


def _read_subset(device: SwOSDevice, subset: str) -> object:
    if subset == "system":
        return _dump(device.get_system_info())
    if subset == "ports":
        return _dump_many(device.get_ports())
    if subset == "port_statistics":
        return _dump_many(device.get_port_statistics())
    if subset == "hosts":
        return _dump_many(device.get_hosts())
    if subset == "rstp":
        return _dump(device.get_rstp())
    if subset == "snmp":
        return _dump(device.get_snmp())
    if subset == "sfp":
        return _dump(device.get_sfp())
    if subset == "forwarding":
        return _dump(device.get_forwarding())
    if subset == "igmp_groups":
        return _dump_many(device.get_igmp_groups())
    if subset == "acl_rules":
        return _dump_many(device.get_acl_rules())
    if subset == "port_vlans":
        return _dump_many(device.get_port_vlans())
    if subset == "vlans":
        return _dump_many(device.get_vlans())
    raise ValueError(f"Unknown facts subset {subset!r}")


def _device_name(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    current = device.get_system_info()
    desired_name = cast(str, params["name"])
    update = DeviceNameUpdate(name=desired_name)
    validation_warnings = device.validate_device_name(update)
    changed = current.name != desired_name
    if check_mode:
        value = current.model_copy(update={"name": desired_name}) if changed else current
        return _with_warnings({"changed": changed, "system": _dump(value)}, validation_warnings)
    if not changed:
        return _with_warnings({"changed": False, "system": _dump(current)}, validation_warnings)
    result = device.set_device_name(update)
    return _with_warnings(
        {"changed": result.changed, "system": _dump(result.value)}, result.warnings
    )


def _port_name(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    number = _ethernet_port(params)
    current = _numbered(device.get_ports(), number, "port")
    desired_name = cast(str, params["name"])
    update = PortNameUpdate(number=number, name=desired_name)
    validation_warnings = device.validate_port_name(update)
    changed = current.name != desired_name
    if check_mode:
        value = current.model_copy(update={"name": desired_name}) if changed else current
        return _with_warnings({"changed": changed, "port": _dump(value)}, validation_warnings)
    if not changed:
        return _with_warnings({"changed": False, "port": _dump(current)}, validation_warnings)
    result = device.set_port_name(update)
    return _with_warnings({"changed": result.changed, "port": _dump(result.value)}, result.warnings)


def _port_configuration(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    number = _ethernet_port(params)
    enabled = _optional_bool(params, "enabled")
    flow_control = _optional_bool(params, "flow_control")
    negotiation = params.get("negotiation")
    speed = params.get("speed_bps")
    duplex = params.get("duplex")
    if enabled is None and flow_control is None and negotiation is None:
        raise ValueError("at least one port configuration option is required")
    if negotiation == "forced":
        if speed is None or duplex is None:
            raise ValueError("negotiation='forced' requires speed_bps and duplex")
        if speed not in (10_000_000, 100_000_000):
            raise ValueError("speed_bps must be 10000000 or 100000000")
        desired_negotiation: Literal["auto"] | ForcedPortNegotiation | None = ForcedPortNegotiation(
            speed_bps=cast(int, speed), duplex=cast(Literal["full", "half"], duplex)
        )
    elif negotiation == "auto":
        if speed is not None or duplex is not None:
            raise ValueError("speed_bps and duplex are valid only with negotiation='forced'")
        desired_negotiation = "auto"
    elif negotiation is None:
        if speed is not None or duplex is not None:
            raise ValueError("speed_bps and duplex are valid only with negotiation='forced'")
        desired_negotiation = None
    else:
        raise ValueError("negotiation must be 'auto' or 'forced'")

    update = PortConfigurationUpdate(
        number=number,
        enabled=enabled,
        negotiation=desired_negotiation,
        flow_control=flow_control,
    )
    current = _numbered(device.get_ports(), number, "port")
    validation_warnings = device.validate_port_configuration(update, current=current)
    projected: JsonObject = {}
    if enabled is not None:
        projected["enabled"] = enabled
    if flow_control is not None:
        projected["flow_control"] = flow_control
    if desired_negotiation == "auto":
        projected["auto_negotiation"] = True
    elif isinstance(desired_negotiation, ForcedPortNegotiation):
        projected.update(
            auto_negotiation=False,
            configured_speed_bps=desired_negotiation.speed_bps,
            configured_full_duplex=desired_negotiation.duplex == "full",
        )
    desired = current.model_copy(update=projected)
    changed = desired != current
    if check_mode:
        return _with_warnings({"changed": changed, "port": _dump(desired)}, validation_warnings)
    if not changed:
        return _with_warnings({"changed": False, "port": _dump(current)}, validation_warnings)
    result = device.set_port_configuration(update)
    return _with_warnings({"changed": result.changed, "port": _dump(result.value)}, result.warnings)


def _snmp_metadata(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    contact = params.get("contact")
    location = params.get("location")
    if contact is None and location is None:
        raise ValueError("at least one of contact or location is required")
    update = SnmpMetadataUpdate(
        contact=cast(str | None, contact),
        location=cast(str | None, location),
    )
    current = device.get_snmp()
    validation_warnings = device.validate_snmp_metadata(update)
    changes: JsonObject = {}
    if update.contact is not None:
        changes["contact"] = update.contact
    if update.location is not None:
        changes["location"] = update.location
    desired = current.model_copy(update=changes)
    changed = desired != current
    if check_mode:
        return _with_warnings({"changed": changed, "snmp": _dump(desired)}, validation_warnings)
    if not changed:
        return _with_warnings({"changed": False, "snmp": _dump(current)}, validation_warnings)
    result = device.set_snmp_metadata(update)
    return _with_warnings({"changed": result.changed, "snmp": _dump(result.value)}, result.warnings)


def _static_hosts(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    desired = tuple(_host(item) for item in params.get("hosts", []))
    identities = [(host.mac_address, host.vlan_id) for host in desired]
    if len(identities) != len(set(identities)):
        raise ValueError("static hosts must have unique MAC and VLAN identities")
    current = tuple(host for host in device.get_hosts() if host.entry_type is HostEntryType.STATIC)
    validation_warnings = device.validate_static_hosts(desired)
    changed = desired != current
    if check_mode:
        return _with_warnings(
            {"changed": changed, "hosts": _dump_many(desired)}, validation_warnings
        )
    if not changed:
        return _with_warnings({"changed": False, "hosts": _dump_many(current)}, validation_warnings)
    result = device.replace_static_hosts(desired, expected_current=current)
    return _with_warnings(
        {"changed": result.changed, "hosts": _dump_many(result.value)}, result.warnings
    )


def _rstp_port(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    number = _ethernet_port(params)
    enabled = cast(bool, params["enabled"])
    current = device.get_rstp()
    port = _numbered(current.ports, number, "RSTP port")
    update = RstpPortEnableUpdate(number=number, enabled=enabled)
    validation_warnings = device.validate_rstp_port_enabled(update, current=current)
    changed = port.enabled != enabled
    desired = current.model_copy(
        update={
            "ports": tuple(
                item.model_copy(update={"enabled": enabled}) if item.number == number else item
                for item in current.ports
            )
        }
    )
    if check_mode:
        return _with_warnings({"changed": changed, "rstp": _dump(desired)}, validation_warnings)
    if not changed:
        return _with_warnings({"changed": False, "rstp": _dump(current)}, validation_warnings)
    result = device.set_rstp_port_enabled(update, expected_current=current)
    return _with_warnings({"changed": result.changed, "rstp": _dump(result.value)}, result.warnings)


def _forwarding_port_policy(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    number = _ethernet_port(params)
    lock = _optional_bool(params, "lock")
    lock_on_first = _optional_bool(params, "lock_on_first")
    rate = params.get("egress_rate_limit_bps")
    if lock is None and lock_on_first is None and rate is None:
        raise ValueError("at least one forwarding policy option is required")
    update = ForwardingPortPolicyUpdate(
        number=number,
        lock=lock,
        lock_on_first=lock_on_first,
        egress_rate_limit_bps=cast(int | Literal["unlimited"] | None, rate),
    )
    current = device.get_forwarding()
    port = _numbered(current.ports, number, "forwarding port")
    validation_warnings = device.validate_forwarding_port_policy(update, current=current)
    port_changes: JsonObject = {}
    if lock is not None:
        port_changes["lock"] = lock
    if lock_on_first is not None:
        port_changes["lock_on_first"] = lock_on_first
    if rate is not None:
        port_changes["egress_rate_limit_bps"] = None if rate == "unlimited" else rate
    desired_port = port.model_copy(update=port_changes)
    changed = desired_port != port
    desired = current.model_copy(
        update={
            "ports": tuple(
                desired_port if item.number == number else item for item in current.ports
            )
        }
    )
    if check_mode:
        return _with_warnings(
            {"changed": changed, "forwarding": _dump(desired)}, validation_warnings
        )
    if not changed:
        return _with_warnings({"changed": False, "forwarding": _dump(current)}, validation_warnings)
    result = device.set_forwarding_port_policy(update, expected_current=current)
    return _with_warnings(
        {"changed": result.changed, "forwarding": _dump(result.value)}, result.warnings
    )


def _vlan_port_policy(
    device: SwOSDevice,
    params: Params,
    check_mode: bool,
    warnings: tuple[SafetyWarning, ...],
) -> JsonObject:
    number = _ethernet_port(params)
    raw_mode = params.get("mode")
    raw_receive = params.get("receive")
    default_vlan_id = params.get("default_vlan_id")
    force_vlan_id = _optional_bool(params, "force_vlan_id")
    raw_egress = params.get("egress")
    if all(
        value is None
        for value in (raw_mode, raw_receive, default_vlan_id, force_vlan_id, raw_egress)
    ):
        raise ValueError("at least one VLAN policy option is required")
    mode = None if raw_mode is None else VlanMode(str(raw_mode))
    receive = None if raw_receive is None else VlanReceiveMode(str(raw_receive))
    egress = None if raw_egress is None else VlanEgressMode(str(raw_egress))
    update = PortVlanPolicyUpdate(
        number=number,
        mode=mode,
        receive=receive,
        default_vlan_id=cast(int | None, default_vlan_id),
        force_vlan_id=force_vlan_id,
        egress=egress,
    )
    current = device.get_port_vlans()
    port = _numbered(current, number, "VLAN port")
    validation_warnings = device.validate_port_vlan_policy(update, current=current)
    changes: JsonObject = {}
    for field, value in (
        ("mode", mode),
        ("receive", receive),
        ("default_vlan_id", update.default_vlan_id),
        ("force_vlan_id", force_vlan_id),
        ("egress", egress),
    ):
        if value is not None:
            changes[field] = value
    desired_port = port.model_copy(update=changes)
    changed = desired_port != port
    desired = tuple(desired_port if item.number == number else item for item in current)
    if check_mode:
        return _with_warnings(
            {"changed": changed, "ports": _dump_many(desired)}, validation_warnings
        )
    if not changed:
        return _with_warnings({"changed": False, "ports": _dump_many(current)}, validation_warnings)
    result = device.set_port_vlan_policy(update, expected_current=current)
    return _with_warnings(
        {"changed": result.changed, "ports": _dump_many(result.value)}, result.warnings
    )


def _validate_operation_params(operation: str, params: Params) -> None:
    if operation == "facts":
        subsets = params.get("gather_subset", ["all"])
        if not isinstance(subsets, list) or any(not isinstance(item, str) for item in subsets):
            raise ValueError("gather_subset must be a list of strings")
        unknown = set(subsets) - FACT_SUBSETS
        if unknown:
            raise ValueError(f"unknown facts subsets: {', '.join(sorted(unknown))}")
        return
    if operation == "device_name":
        _validate_ascii(params.get("name"), "device name", MAX_DEVICE_NAME_BYTES)
        return
    if operation == "port_name":
        _validate_port_param(params)
        _validate_ascii(params.get("name"), "port name", MAX_PORT_NAME_BYTES)
        return
    if operation == "port_configuration":
        number = _validate_port_param(params)
        enabled = _validate_optional_bool(params, "enabled")
        flow_control = _validate_optional_bool(params, "flow_control")
        negotiation = params.get("negotiation")
        speed = params.get("speed_bps")
        duplex = params.get("duplex")
        if enabled is None and flow_control is None and negotiation is None:
            raise ValueError("at least one port configuration option is required")
        if negotiation == "forced":
            if speed is None or duplex is None:
                raise ValueError("negotiation='forced' requires speed_bps and duplex")
            if type(speed) is not int or speed not in (10_000_000, 100_000_000):
                raise ValueError("speed_bps must be 10000000 or 100000000")
            if duplex not in ("full", "half"):
                raise ValueError("negotiation='forced' requires duplex 'full' or 'half'")
            desired: Literal["auto"] | ForcedPortNegotiation = ForcedPortNegotiation(
                speed_bps=speed,
                duplex=cast(Literal["full", "half"], duplex),
            )
        elif negotiation == "auto":
            if speed is not None or duplex is not None:
                raise ValueError("speed_bps and duplex are valid only with negotiation='forced'")
            desired = "auto"
        elif negotiation is None:
            if speed is not None or duplex is not None:
                raise ValueError("speed_bps and duplex are valid only with negotiation='forced'")
            desired = "auto"
        else:
            raise ValueError("negotiation must be 'auto' or 'forced'")
        PortConfigurationUpdate(
            number=number,
            enabled=enabled,
            negotiation=None if negotiation is None else desired,
            flow_control=flow_control,
        )
        return
    if operation == "snmp_metadata":
        contact = params.get("contact")
        location = params.get("location")
        if contact is None and location is None:
            raise ValueError("at least one of contact or location is required")
        if contact is not None:
            _validate_ascii(contact, "SNMP contact", MAX_SNMP_METADATA_BYTES)
        if location is not None:
            _validate_ascii(location, "SNMP location", MAX_SNMP_METADATA_BYTES)
        SnmpMetadataUpdate(contact=contact, location=location)
        return
    if operation == "static_hosts":
        hosts = params.get("hosts")
        if not isinstance(hosts, list):
            raise ValueError("hosts must be a list")
        if len(hosts) > MAX_STATIC_HOSTS:
            raise ValueError(f"static host table cannot exceed {MAX_STATIC_HOSTS} entries")
        parsed = tuple(_host(item) for item in hosts)
        identities = [(host.mac_address, host.vlan_id) for host in parsed]
        if len(identities) != len(set(identities)):
            raise ValueError("static hosts must have unique MAC and VLAN identities")
        return
    if operation == "rstp_port":
        number = _validate_port_param(params)
        enabled = _require_bool(params.get("enabled"), "enabled")
        RstpPortEnableUpdate(number=number, enabled=enabled)
        return
    if operation == "forwarding_port_policy":
        number = _validate_port_param(params)
        lock = _validate_optional_bool(params, "lock")
        lock_on_first = _validate_optional_bool(params, "lock_on_first")
        rate = params.get("egress_rate_limit_bps")
        if lock is None and lock_on_first is None and rate is None:
            raise ValueError("at least one forwarding policy option is required")
        if rate is not None and rate != "unlimited":
            if type(rate) is not int:
                raise ValueError("egress_rate_limit_bps must be an integer or 'unlimited'")
            if rate < 1 or rate > 0xFFFFFFFF:
                raise ValueError("egress_rate_limit_bps must be between 1 and 4294967295")
        ForwardingPortPolicyUpdate(
            number=number,
            lock=lock,
            lock_on_first=lock_on_first,
            egress_rate_limit_bps=cast(int | Literal["unlimited"] | None, rate),
        )
        return
    if operation == "vlan_port_policy":
        number = _validate_port_param(params)
        mode = params.get("mode")
        receive = params.get("receive")
        vlan_id = params.get("default_vlan_id")
        force = _validate_optional_bool(params, "force_vlan_id")
        egress = params.get("egress")
        if all(value is None for value in (mode, receive, vlan_id, force, egress)):
            raise ValueError("at least one VLAN policy option is required")
        if mode is not None and mode not in {item.value for item in VlanMode}:
            raise ValueError("invalid VLAN mode")
        if receive is not None and receive not in {item.value for item in VlanReceiveMode}:
            raise ValueError("invalid VLAN receive mode")
        if egress is not None and egress not in {item.value for item in VlanEgressMode}:
            raise ValueError("invalid VLAN egress mode")
        if vlan_id is not None and (type(vlan_id) is not int or vlan_id < 1 or vlan_id > 4095):
            raise ValueError("default_vlan_id must be between 1 and 4095")
        PortVlanPolicyUpdate(
            number=number,
            mode=mode,
            receive=receive,
            default_vlan_id=vlan_id,
            force_vlan_id=force,
            egress=egress,
        )
        return
    raise ValueError(f"Unknown swos-ansible operation {operation!r}")


def _validate_port_param(params: Params) -> int:
    number = params.get("port")
    if type(number) is not int or number < 1 or number > 5:
        raise ValueError("port must be an Ethernet port from 1 through 5")
    return number


def _validate_optional_bool(params: Params, name: str) -> bool | None:
    value = params.get(name)
    return None if value is None else _require_bool(value, name)


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _validate_ascii(value: object, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must contain printable ASCII only") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(f"{label} must contain printable ASCII only")
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{label} cannot exceed {maximum_bytes} characters")
    return value


def _host(raw: object) -> HostEntry:
    if not isinstance(raw, Mapping):
        raise ValueError("each static host must be a mapping")
    raw_ports = raw.get("port_numbers", [])
    if not isinstance(raw_ports, list) or any(type(number) is not int for number in raw_ports):
        raise ValueError("static host port_numbers must be a list of integers")
    ports = tuple(sorted(raw_ports))
    if any(number < 1 or number > 5 for number in ports):
        raise ValueError("static host port_numbers must contain only ports 1-5")
    mac_address = raw.get("mac_address")
    vlan_id = raw.get("vlan_id")
    drop = raw.get("drop", False)
    mirror = raw.get("mirror", False)
    if not isinstance(mac_address, str):
        raise ValueError("static host mac_address must be a string")
    if type(vlan_id) is not int or vlan_id < 1 or vlan_id > 4095:
        raise ValueError("static host vlan_id must be between 1 and 4095")
    drop = _require_bool(drop, "static host drop")
    mirror = _require_bool(mirror, "static host mirror")
    return HostEntry(
        entry_type=HostEntryType.STATIC,
        mac_address=mac_address,
        vlan_id=vlan_id,
        port_numbers=ports,
        drop=drop,
        mirror=mirror,
    )


def _ethernet_port(params: Params) -> int:
    number = cast(int, params["port"])
    if number < 1 or number > 5:
        raise ValueError("port must be an Ethernet port from 1 through 5")
    return number


def _optional_bool(params: Params, name: str) -> bool | None:
    value = params.get(name)
    return cast(bool | None, value)


def _numbered(items: Sequence[Numbered], number: int, label: str) -> Numbered:
    try:
        return next(item for item in items if item.number == number)
    except StopIteration as exc:
        raise ValueError(f"{label} {number} was not returned by the device") from exc


def _dump(value: _Serializable) -> JsonObject:
    return value.model_dump(mode="json")


def _dump_many(values: Sequence[_Serializable]) -> list[JsonObject]:
    return [_dump(value) for value in values]


def _with_warnings(result: JsonObject, warnings: tuple[SafetyWarning, ...]) -> JsonObject:
    if warnings:
        result["swos_warnings"] = [warning.model_dump(mode="json") for warning in warnings]
        result["warnings"] = [warning.message for warning in warnings]
    return result
