import pytest
from unittest.mock import MagicMock
from app.utils.request import get_client_ip


def test_get_client_ip_from_x_forwarded_for():
    request = MagicMock()
    request.headers = {"X-Forwarded-For": "203.0.113.195, 70.41.3.18, 150.172.238.178"}
    request.client = MagicMock(host="10.0.0.1")

    assert get_client_ip(request) == "203.0.113.195"


def test_get_client_ip_from_x_real_ip():
    request = MagicMock()
    request.headers = {"X-Real-IP": "203.0.113.195"}
    request.client = MagicMock(host="10.0.0.1")

    assert get_client_ip(request) == "203.0.113.195"


def test_get_client_ip_direct():
    request = MagicMock()
    request.headers = {}
    request.client = MagicMock(host="192.168.1.100")

    assert get_client_ip(request) == "192.168.1.100"


def test_get_client_ip_no_client():
    request = MagicMock()
    request.headers = {}
    request.client = None

    assert get_client_ip(request) == "unknown"
