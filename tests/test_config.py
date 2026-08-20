import pytest

from core.config import Settings


def test_defaults_without_env():
    settings = Settings(_env_file=None, bot_token="123:test")
    assert settings.bot_token.get_secret_value() == "123:test"
    assert settings.log_level == "INFO"
    assert settings.request_timeout == 10.0
    assert settings.virustotal_api_key is None
    assert settings.urlhaus_api_key is None
    assert settings.google_safebrowsing_api_key is None


def test_env_variables_loaded(monkeypatch):
    monkeypatch.setenv("BOT_TOKEN", "456:envtoken")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("REQUEST_TIMEOUT", "5.5")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setenv("URLHAUS_API_KEY", "uh-key")
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "gsb-key")
    settings = Settings(_env_file=None)
    assert settings.bot_token.get_secret_value() == "456:envtoken"
    assert settings.log_level == "DEBUG"
    assert settings.request_timeout == 5.5
    assert settings.virustotal_api_key == "vt-key"
    assert settings.urlhaus_api_key == "uh-key"
    assert settings.google_safebrowsing_api_key == "gsb-key"


def test_missing_bot_token_raises(monkeypatch):
    for key in ("BOT_TOKEN", "VIRUSTOTAL_API_KEY", "URLHAUS_API_KEY", "GOOGLE_SAFEBROWSING_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(Exception):
        Settings(_env_file=None)


def test_log_level_upper_property():
    settings = Settings(_env_file=None, bot_token="123:test", log_level="debug")
    assert settings.log_level_upper == "DEBUG"