"""Ansible-independent execution support for the swos.api collection."""

from importlib.metadata import PackageNotFoundError, version

from swos_ansible.runtime import execute

try:
    __version__ = version("swos-ansible")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["__version__", "execute"]
