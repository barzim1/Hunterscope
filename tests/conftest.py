from pathlib import Path

import pytest

from hunterscope.config.loader import load_rules_config
from hunterscope.ingest import load_events

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(scope="session")
def cfg():
    return load_rules_config()


@pytest.fixture(scope="session")
def loaded():
    return load_events([SAMPLES])
