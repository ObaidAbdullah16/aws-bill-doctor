import datetime as dt

import boto3
import pytest
from moto import mock_aws

from billdoctor.models import ScanContext
from billdoctor.pricing import Prices

REGION = "ap-south-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    # Make sure no real credentials are ever used by tests
    for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def now():
    return dt.datetime.now(dt.timezone.utc)


@pytest.fixture
def ctx(aws, now):
    return ScanContext(aws, REGION, Prices(), now=now)
