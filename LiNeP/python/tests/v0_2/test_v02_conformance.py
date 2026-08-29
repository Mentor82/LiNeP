"""Tests for the LiNeP V0.2 Python Conformance Test Engine."""

import pytest
from linep.v0_2 import (
    RuntimeProfile,
    LiNePMockServer,
    MockServerConfig,
    ConformanceRunner,
)


@pytest.fixture
def conformance_server():
    server = LiNePMockServer(MockServerConfig(model_id="conformance-model"))
    server.start(tcp_port=0)
    yield server
    server.stop()


def test_conformance_runner_all_suites(conformance_server):
    runner = ConformanceRunner(port=conformance_server.tcp_port)
    rep = runner.run_all()

    assert rep.total_tests == 9
    assert rep.passed_tests == 9
    assert rep.failed_tests == 0
    assert rep.is_all_passed() is True

    # Assert all profiles conformant
    profiles_dict = {p.profile: p.conformant for p in rep.profiles}
    assert profiles_dict[RuntimeProfile.GENERATE] is True
    assert profiles_dict[RuntimeProfile.CHAT] is True
    assert profiles_dict[RuntimeProfile.EMBED] is True
