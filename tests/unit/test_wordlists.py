from pathlib import Path

import pytest

from adi.tools.wordlists import WordlistNotFoundError, resolve_web_content_wordlist

TINY_WORDLIST = Path(__file__).resolve().parents[1] / "fixtures" / "wordlists" / "tiny.txt"


def test_configured_path_used_when_it_exists():
    assert resolve_web_content_wordlist(str(TINY_WORDLIST)) == str(TINY_WORDLIST)


def test_configured_path_ignored_when_missing_falls_back_or_raises(monkeypatch):
    monkeypatch.setattr("adi.tools.wordlists._COMMON_WEB_CONTENT_PATHS", [])
    with pytest.raises(WordlistNotFoundError):
        resolve_web_content_wordlist("/nonexistent/path.txt")


def test_no_configured_path_and_no_common_path_raises_clear_error(monkeypatch):
    monkeypatch.setattr("adi.tools.wordlists._COMMON_WEB_CONTENT_PATHS", [])
    with pytest.raises(WordlistNotFoundError, match="no web-content wordlist found"):
        resolve_web_content_wordlist(None)


def test_common_path_used_when_available(monkeypatch):
    monkeypatch.setattr("adi.tools.wordlists._COMMON_WEB_CONTENT_PATHS", [str(TINY_WORDLIST)])
    assert resolve_web_content_wordlist(None) == str(TINY_WORDLIST)
