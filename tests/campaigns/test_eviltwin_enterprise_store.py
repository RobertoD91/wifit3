"""Enterprise credential store: correct file per kind, deduped."""
from wifit3.campaigns.eviltwin_enterprise.eap_server import Capture
from wifit3.campaigns.eviltwin_enterprise.store import save_capture


def _read(path):
    return path.read_text("utf-8").splitlines()


def test_mschapv2_written_to_hc5500_and_deduped(tmp_path):
    cap = Capture(ssid="CorpNet", username="alice", inner_method="MSCHAPv2",
                  hashline="alice::::" + "ab" * 24 + ":" + "cd" * 8)
    path = save_capture(cap, tmp_path)
    assert path.name.endswith("_enterprise.hc5500")
    save_capture(cap, tmp_path)                           # same capture again
    assert _read(path) == [cap.hashline]                 # deduped to one line


def test_gtc_plaintext_and_identity_go_to_their_own_files(tmp_path):
    gtc = save_capture(Capture(ssid="CorpNet", username="bob", inner_method="GTC",
                               password="hunter2"), tmp_path)
    ident = save_capture(Capture(ssid="CorpNet", username="eve@corp", inner_method="Identity"),
                         tmp_path)
    assert gtc.name.endswith("_enterprise_plain.txt") and _read(gtc) == ["bob:hunter2"]
    assert ident.name.endswith("_eap_identities.txt") and _read(ident) == ["eve@corp"]


def test_empty_username_is_not_saved(tmp_path):
    assert save_capture(Capture(ssid="X", username="", inner_method="Identity"), tmp_path) is None
    assert list(tmp_path.iterdir()) == []
