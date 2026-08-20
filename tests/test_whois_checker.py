from types import SimpleNamespace

import pytest

from analyzer.whois_checker import check_whois


def _fake_whois_package(data: object) -> SimpleNamespace:
    return SimpleNamespace(whois=lambda domain: data)


class FakeWhoisData:
    domain_name = ["example.com"]
    registrar = "GoDaddy LLC"
    creation_date = "2020-01-01 00:00:00"
    expiration_date = "2026-01-01 00:00:00"
    country = "US"


async def test_check_whois_returns_info(monkeypatch):
    monkeypatch.setattr(
        "analyzer.whois_checker.whois", _fake_whois_package(FakeWhoisData())
    )
    info = await check_whois("example.com")
    assert info.domain == "example.com"
    assert info.registrar == "GoDaddy LLC"
    assert info.creation_date == "2020-01-01 00:00:00"
    assert info.expiration_date == "2026-01-01 00:00:00"
    assert info.country == "US"


async def test_check_whois_missing_fields_become_none(monkeypatch):
    monkeypatch.setattr(
        "analyzer.whois_checker.whois",
        _fake_whois_package(SimpleNamespace(domain_name=["example.com"])),
    )
    info = await check_whois("example.com")
    assert info.registrar is None
    assert info.creation_date is None
    assert info.expiration_date is None
    assert info.country is None


async def test_check_whois_raises_when_domain_missing(monkeypatch):
    monkeypatch.setattr(
        "analyzer.whois_checker.whois",
        _fake_whois_package(SimpleNamespace(domain_name=[])),
    )
    with pytest.raises(ValueError, match="ma'lumotlari topilmadi"):
        await check_whois("example.com")