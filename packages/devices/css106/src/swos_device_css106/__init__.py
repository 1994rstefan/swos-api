"""CSS106 device plugin package."""

from importlib.metadata import PackageNotFoundError, version

from swos_device_css106.plugin import CSS106Plugin, plugin

try:
    __version__ = version("swos-device-css106")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["CSS106Plugin", "__version__", "plugin"]
