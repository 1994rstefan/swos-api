import pytest

from conftest import _high_risk_tables_gate_enabled


class _Config:
    def __init__(self, values: dict[str, bool]) -> None:
        self.values = values

    def getoption(self, name: str) -> bool:
        return self.values[name]


@pytest.mark.parametrize(
    ("values", "enabled"),
    [
        (
            {"--run-integration": True, "--run-destructive": True, "--run-high-risk-tables": True},
            True,
        ),
        (
            {
                "--run-integration": False,
                "--run-destructive": True,
                "--run-high-risk-tables": True,
            },
            False,
        ),
        (
            {
                "--run-integration": True,
                "--run-destructive": False,
                "--run-high-risk-tables": True,
            },
            False,
        ),
        (
            {
                "--run-integration": True,
                "--run-destructive": True,
                "--run-high-risk-tables": False,
            },
            False,
        ),
    ],
)
def test_high_risk_tables_gate_requires_all_three_options(
    values: dict[str, bool], enabled: bool
) -> None:
    config = _Config(values)

    assert _high_risk_tables_gate_enabled(config) is enabled  # type: ignore[arg-type]
