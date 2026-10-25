import io
import json

from phishsentinel.__main__ import main


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    return code, capsys.readouterr().out


def test_ledger_lists_signals_by_weight(tmp_path, capsys):
    f = tmp_path / "mail.txt"
    f.write_text("Please click here: http://192.0.2.10/page")
    code, out = run(capsys, [str(f)])
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("Rule-engine risk:")
    assert "raw_ip_link" in lines[1] and "call_to_action" in lines[2]


def test_json_output_from_stdin(capsys, monkeypatch):
    code, out = run(capsys, ["--json"], stdin="see https://www.amazon.com/orders", monkeypatch=monkeypatch)
    data = json.loads(out)
    assert code == 0 and data["urls"] == ["https://www.amazon.com/orders"]
    assert data["rule_logodds"] < 0


def test_no_signals_message(tmp_path, capsys):
    f = tmp_path / "plain.txt"
    f.write_text("lunch at noon?")
    assert "no deterministic signals" in run(capsys, [str(f)])[1]
