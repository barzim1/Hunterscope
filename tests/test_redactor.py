import pytest

from hunterscope.config.loader import load_redactor_config
from hunterscope.redactor import Redactor, valid_pesel


@pytest.fixture
def red():
    return Redactor(load_redactor_config(), known_users=["jkowalski"], known_hosts=["srv-db01"])


def test_valid_pesel_checksum():
    assert valid_pesel("44051401359")
    assert not valid_pesel("44051401358")
    assert not valid_pesel("1234")


def test_pesel_redacted_only_when_checksum_valid(red):
    out = red.redact("id 44051401359 and order 12345678901")
    assert "44051401359" not in out and "PII_ID_1" in out
    assert "12345678901" in out


def test_same_user_gets_same_label_across_formats(red):
    out = red.redact("jkowalski@contoso.com / CONTOSO\\JKowalski / jkowalski")
    assert out == "USER_A@INTERNAL_DOMAIN / USER_A / USER_A"


def test_different_users_get_different_labels(red):
    out = red.redact("a@contoso.com b@contoso.com a@contoso.com")
    assert out == "USER_A@INTERNAL_DOMAIN USER_B@INTERNAL_DOMAIN USER_A@INTERNAL_DOMAIN"


def test_private_ip_masked_public_kept_by_default(red):
    out = red.redact("10.20.4.15 -> 203.0.113.50, again 10.20.4.15, other 192.168.1.1")
    assert out == "INTERNAL_IP_1 -> 203.0.113.50, again INTERNAL_IP_1, other INTERNAL_IP_2"


def test_public_ip_masked_when_configured():
    cfg = load_redactor_config()
    cfg["keep_public_ips"] = False
    out = Redactor(cfg).redact("203.0.113.50 and 203[.]0[.]113[.]50")
    assert out == "IP_1 and IP_1"


def test_invalid_ip_like_strings_untouched(red):
    assert red.redact("version 999.1.1.1 build") == "version 999.1.1.1 build"


def test_external_email_masked(red):
    assert red.redact("fwd to x@evil.test") == "fwd to EXT_EMAIL_1"


def test_fqdn_becomes_host_label_and_domain_label(red):
    out = red.redact("srv-db01.contoso.com ws9.contoso.com contoso.com")
    assert out == "HOST_1 HOST_2 INTERNAL_DOMAIN_1"


def test_username_inside_hostname_is_caught(red):
    assert "kowalski" not in red.redact("WS-JKOWALSKI").lower()


def test_extra_pattern(red):
    assert red.redact("badge EMP123456") == "badge EMPLOYEE_ID_1"


def test_hmac_labels_stable_across_runs_and_key_dependent():
    cfg = load_redactor_config()
    a = Redactor(cfg, key=b"k1").redact("jane@contoso.com")
    assert a == Redactor(cfg, key=b"k1").redact("jane@contoso.com")
    assert a != Redactor(cfg, key=b"k2").redact("jane@contoso.com")
    assert "jane" not in a


def test_mapping_roundtrip(red):
    red.redact("10.0.0.5 a@contoso.com")
    assert red.mapping() == {"INTERNAL_IP_1": "10.0.0.5", "USER_A": "a"}


def test_redaction_is_single_pass_no_cascade(red):
    assert red.redact("INTERNAL_IP_1") == "INTERNAL_IP_1"
