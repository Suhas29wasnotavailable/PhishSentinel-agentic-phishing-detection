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


def test_fail_above_sets_exit_code(tmp_path, capsys):
    f = tmp_path / "mail.txt"
    f.write_text("Please click here: http://192.0.2.10/page")
    assert run(capsys, [str(f), "--fail-above", "0.5"])[0] == 2
    assert run(capsys, [str(f), "--fail-above", "0.99"])[0] == 0


def test_several_files_give_a_ranked_summary(tmp_path, capsys):
    risky, plain = tmp_path / "risky.txt", tmp_path / "plain.txt"
    risky.write_text("Please click here: http://192.0.2.10/page")
    plain.write_text("lunch at noon?")
    code, out = run(capsys, [str(plain), str(risky)])
    first, second = out.splitlines()
    assert code == 0
    assert first.endswith("risky.txt") and "raw_ip_link" in first
    assert second.endswith("plain.txt")
    code, out = run(capsys, [str(plain), str(risky), "--json", "--fail-above", "0.5"])
    assert code == 2
    assert [json.loads(line)["file"] for line in out.splitlines()] == [str(risky), str(plain)]


def test_iocs_flag_prints_defanged_indicators(tmp_path, capsys):
    f = tmp_path / "mail.txt"
    f.write_text("Please click here: http://192.0.2.10/page")
    out = run(capsys, [str(f), "--iocs"])[1]
    assert "urls         hxxp://192[.]0[.]2[.]10/page" in out
    assert json.loads(run(capsys, [str(f), "--iocs", "--json"])[1])["ips"] == ["192[.]0[.]2[.]10"]
