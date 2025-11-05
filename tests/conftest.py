from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--force-native", action="store_true", default=False, help="run native tests, not allowing fallbacks"
    )
