import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_retry_pauses(monkeypatch):
    """Повторы при перегрузке сервера — без пауз: тесты проверяют поведение, а не время ожидания."""
    import collector
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: None)
