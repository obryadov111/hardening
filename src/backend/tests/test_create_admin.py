"""python -m app.commands.create_admin: пароль скрыт при вводе и проверяется по правилам интерфейса."""
from sqlalchemy import text

from app.commands.create_admin import main
from app.core.security import verify_password


def run(answers, secrets):
    answers, secrets = iter(answers), iter(secrets)
    return main(ask=lambda _: next(answers), ask_secret=lambda _: next(secrets))


def test_creates_superadmin_with_hashed_password(db, capsys):
    assert run(["  Root@Example.COM ", "Главный"], ["Long-enough-pass-1", "Long-enough-pass-1"]) == 0
    row = db.execute(text("SELECT email, is_superadmin, password_hash, full_name FROM users")).one()
    assert row.email == "root@example.com" and row.is_superadmin and row.full_name == "Главный"
    assert verify_password("Long-enough-pass-1", row.password_hash)
    assert "Админ создан" in capsys.readouterr().out


def test_refuses_weak_mismatched_duplicate_and_bad_email(db, capsys, make_user):
    assert run(["root@example.com"], ["short"]) == 1
    assert "короче 12 символов" in capsys.readouterr().out
    assert run(["root@example.com"], ["Long-enough-pass-1", "Long-enough-pass-2"]) == 1
    assert "не совпадают" in capsys.readouterr().out
    assert run(["root@example.com"], ["root@example.com"]) == 1
    assert "не должен совпадать с email" in capsys.readouterr().out
    assert run(["no-at-sign"], []) == 1
    make_user("taken@example.com")
    assert run(["taken@example.com"], []) == 1
    assert "уже существует" in capsys.readouterr().out
    assert db.execute(text("SELECT count(*) FROM users WHERE is_superadmin")).scalar() == 0
