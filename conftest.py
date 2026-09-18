"""Explicit opt-in gates for tests that interact with physical devices."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run tests that require a physical SwOS device.",
    )
    parser.addoption(
        "--run-destructive",
        action="store_true",
        default=False,
        help="Allow integration tests that modify a physical SwOS device.",
    )
    parser.addoption(
        "--run-password-rotation",
        action="store_true",
        default=False,
        help="Allow the destructive administrator password rotation test.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_integration = config.getoption("--run-integration")
    run_destructive = config.getoption("--run-destructive")
    run_password_rotation = config.getoption("--run-password-rotation")
    skip_integration = pytest.mark.skip(reason="requires --run-integration")
    skip_destructive = pytest.mark.skip(
        reason="requires both --run-integration and --run-destructive"
    )
    skip_password_rotation = pytest.mark.skip(
        reason=("requires --run-integration, --run-destructive, and --run-password-rotation")
    )

    for item in items:
        password_rotation = item.get_closest_marker("password_rotation") is not None
        destructive = item.get_closest_marker("destructive") is not None
        integration = item.get_closest_marker("integration") is not None
        if password_rotation and not (
            run_integration and run_destructive and run_password_rotation
        ):
            item.add_marker(skip_password_rotation)
        elif destructive and not (run_integration and run_destructive):
            item.add_marker(skip_destructive)
        elif integration and not run_integration:
            item.add_marker(skip_integration)
