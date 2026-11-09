import pytest
from sentinel.config import Settings
from sentinel.container import Container


@pytest.fixture(scope="session")
def trained():
    return Container(Settings()).detectors          # train once for the whole test session


@pytest.fixture
def container(trained):
    return Container(Settings(), detectors=trained)
