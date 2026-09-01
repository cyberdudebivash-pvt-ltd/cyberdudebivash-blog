"""Shared pytest isolation for integration fixtures.

The production Blogger pipeline deliberately prefers the checked-out canonical
``rss.xml`` before the remote RSS endpoint.  ``tests/test_integration.py`` is a
closed-system simulation whose external inputs are intentionally supplied by
HTTP mocks (``MOCK_RSS``); allowing the repository's real production RSS
artifact into those cases makes the fixture nondeterministic and can consume
more mocked Blogger responses than the scenario defines.

Keep that one integration module hermetic while leaving the dedicated
``test_canonical_rss.py`` and scheduler tests to exercise the real local-handoff
implementation directly.
"""

import pytest


@pytest.fixture(autouse=True)
def isolate_repository_rss_from_mocked_integration_tests(request, monkeypatch):
    """Do not mix the repository's live RSS artifact into mocked integration tests."""
    if request.node.path.name == "test_integration.py":
        monkeypatch.setattr(
            "automation.main.discover_local_canonical_rss",
            lambda *args, **kwargs: [],
        )
