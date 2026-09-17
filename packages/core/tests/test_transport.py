import httpx
import pytest
from swos_core.errors import AuthenticationError, TransportError
from swos_core.models import DeviceConnection
from swos_core.transport import HttpTransport


def make_transport(handler: httpx.MockTransport) -> HttpTransport:
    return HttpTransport(DeviceConnection(url="http://192.0.2.1"), transport=handler)


def test_transport_returns_raw_response() -> None:
    mock = httpx.MockTransport(lambda request: httpx.Response(200, content=b"{upt:0x01}"))

    with make_transport(mock) as transport:
        assert transport.request("GET", "/sys.b") == b"{upt:0x01}"


def test_transport_normalizes_authentication_failure() -> None:
    mock = httpx.MockTransport(lambda request: httpx.Response(401))

    with make_transport(mock) as transport, pytest.raises(AuthenticationError):
        transport.request("GET", "/sys.b")


def test_transport_normalizes_server_failure() -> None:
    mock = httpx.MockTransport(lambda request: httpx.Response(500))

    with make_transport(mock) as transport, pytest.raises(TransportError) as error:
        transport.request("GET", "/sys.b")

    assert "HTTP 500" in str(error.value)


def test_transport_normalizes_timeout() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    with make_transport(httpx.MockTransport(timeout)) as transport:
        with pytest.raises(TransportError, match="timed out"):
            transport.request("GET", "/sys.b")


@pytest.mark.parametrize(
    "endpoint",
    ["http://198.51.100.1/collect", "//198.51.100.1/collect"],
)
def test_transport_rejects_cross_origin_endpoint(endpoint: str) -> None:
    mock = httpx.MockTransport(lambda request: httpx.Response(200))

    with make_transport(mock) as transport, pytest.raises(TransportError, match="must be a path"):
        transport.request("GET", endpoint)


def test_transport_normalizes_request_failure() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("failed", request=request)

    with make_transport(httpx.MockTransport(fail)) as transport:
        with pytest.raises(TransportError, match="request failed"):
            transport.request("GET", "/sys.b")
