"""Shared synchronous HTTP transport for SwOS device plugins."""

from __future__ import annotations

from types import TracebackType
from urllib.parse import urlsplit

import httpx

from swos_core.errors import AuthenticationError, TransportError
from swos_core.models import DeviceConnection


class HttpTransport:
    """Small Digest-authenticated HTTP transport with normalized errors."""

    def __init__(
        self,
        connection: DeviceConnection,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=str(connection.url).rstrip("/") + "/",
            auth=httpx.DigestAuth(
                connection.username,
                connection.password.get_secret_value(),
            ),
            timeout=connection.timeout,
            verify=connection.verify_tls,
            transport=transport,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        content: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        """Perform a request and return the raw response body."""

        endpoint = urlsplit(path)
        if endpoint.scheme or endpoint.netloc:
            raise TransportError("SwOS endpoint must be a path on the configured device")

        try:
            response = self._client.request(
                method,
                path.lstrip("/"),
                content=content,
                headers=headers,
            )
            if response.status_code in {401, 403}:
                raise AuthenticationError("The SwOS device rejected the supplied credentials")
            response.raise_for_status()
        except AuthenticationError:
            raise
        except httpx.TimeoutException as exc:
            raise TransportError("The SwOS device request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise TransportError(
                f"The SwOS device returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise TransportError("The SwOS device request failed") from exc
        return response.content

    def close(self) -> None:
        """Close the underlying connection pool."""

        self._client.close()

    def __enter__(self) -> HttpTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
