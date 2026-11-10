"""TLS server context: bundled cert loads, a custom PEM path is honoured, a missing one is a
clear error."""
import pytest

from wifit3.campaigns.eviltwin_enterprise.tls import CERT_PATH, describe_cert, server_context


def test_bundled_cert_loads():
    assert server_context() is not None


def test_custom_cert_path_is_loaded():
    # The bundled PEM, passed explicitly, exercises the custom-path branch.
    assert server_context(str(CERT_PATH)) is not None


def test_missing_custom_cert_raises_clear_error(tmp_path):
    with pytest.raises(ValueError, match="certificate not found"):
        server_context(str(tmp_path / "does-not-exist.pem"))


def test_describe_cert_reports_cn_and_self_signed():
    described = describe_cert()
    assert "radius.local" in described and "self-signed" in described


def test_describe_cert_is_best_effort_on_bad_path(tmp_path):
    # Never raises (a demo log must not break the twin); falls back to a generic label.
    assert describe_cert(str(tmp_path / "nope.pem")) == "custom certificate"
