"""Read-only CSS106 adapter."""

from __future__ import annotations

from collections.abc import Callable

from swos_core.errors import ProtocolError
from swos_core.models import DeviceCapabilities, DeviceConnection, DeviceIdentity, SystemInfo
from swos_core.transport import HttpTransport

from swos_device_css106.protocol import (
    MAX_PAYLOAD_BYTES,
    identity_from_system,
    parse_payload,
    system_info_from_payload,
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
        return DeviceCapabilities(features=frozenset({"system"}))

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
