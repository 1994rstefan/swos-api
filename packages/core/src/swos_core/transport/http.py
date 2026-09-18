"""Shared synchronous HTTP transport for SwOS device plugins."""

from __future__ import annotations

from types import TracebackType
from urllib.parse import urlsplit

import httpx

from swos_core.errors import AuthenticationError, HttpStatusError, TransportError
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
        max_response_bytes: int | None = None,
    ) -> bytes:
        """Perform a request and return the raw response body."""

        endpoint = urlsplit(path)
        if endpoint.scheme or endpoint.netloc:
            raise TransportError("SwOS endpoint must be a path on the configured device")
        if max_response_bytes is not None and max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        request_headers = dict(headers or {})
        if max_response_bytes is not None:
            request_headers["Accept-Encoding"] = "identity"

        try:
            with self._client.stream(
                method,
                path.lstrip("/"),
                content=content,
                headers=request_headers,
            ) as response:
                if response.status_code in {401, 403}:
                    raise AuthenticationError("The SwOS device rejected the supplied credentials")
                response.raise_for_status()
                if max_response_bytes is None:
                    return response.read()
                content_encoding = response.headers.get("Content-Encoding", "identity")
                if content_encoding.casefold() != "identity":
                    raise TransportError(
                        "Encoded SwOS responses are not accepted for size-limited requests"
                    )
                body = bytearray()
                for chunk in response.iter_raw():
                    if len(chunk) > max_response_bytes - len(body):
                        raise TransportError("The SwOS device response exceeded the safety limit")
                    body.extend(chunk)
                return bytes(body)
        except AuthenticationError:
            raise
        except httpx.TimeoutException as exc:
            raise TransportError("The SwOS device request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise HttpStatusError(exc.response.status_code) from exc
        except httpx.RequestError as exc:
            raise TransportError("The SwOS device request failed") from exc

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
