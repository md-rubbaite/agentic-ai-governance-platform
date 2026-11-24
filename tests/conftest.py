from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentgov.cli import default_policy_text, seed_demo
from agentgov.service import GovernanceService
from agentgov.store import Store


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 24, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def service(clock: Clock) -> GovernanceService:
    return GovernanceService(Store(":memory:"), clock=clock)


@pytest.fixture
def seeded(service: GovernanceService) -> tuple[GovernanceService, dict[str, str]]:
    keys = seed_demo(service)
    return service, keys


@pytest.fixture
def policy_text() -> str:
    return default_policy_text()
