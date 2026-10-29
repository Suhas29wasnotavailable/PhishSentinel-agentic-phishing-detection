import re
from pathlib import Path

from phishsentinel.mitre import TECHNIQUES, technique_url


def test_every_technique_used_by_a_signal_has_a_name():
    source = Path(__file__).resolve().parents[1].joinpath("phishsentinel", "forensics.py").read_text()
    used = set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', source))
    assert used and used <= set(TECHNIQUES)


def test_sub_technique_url():
    assert technique_url("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"
