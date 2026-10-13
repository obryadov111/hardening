"""Создание суперадминистратора на сервере (через API суперадмина не создать).

Usage: python -m app.commands.create_admin
Пароль вводится без отображения на экране и проверяется по тем же правилам, что пароли из интерфейса.
"""
from getpass import getpass

from sqlalchemy.orm import Session

from app.core.security import hash_password, password_problem
from app.db.session import SessionLocal
from app.models.user import User


def main(ask=input, ask_secret=getpass) -> int:
    db: Session = SessionLocal()
    try:
        email = ask("Admin email: ").strip().lower()
        if "@" not in email:
            print("Ошибка: нужен email")
            return 1
        if db.query(User).filter(User.email == email).first():
            print("Пользователь уже существует")
            return 1
        password = ask_secret("Admin password: ")
        problem = password_problem(password, email)
        if problem:
            print(f"Ошибка: {problem}")
            return 1
        if ask_secret("Repeat password: ") != password:
            print("Ошибка: пароли не совпадают")
            return 1
        display_name = ask("Display name: ").strip()

        user = User(
            email=email,
            password_hash=hash_password(password),
            display_name=display_name or None,
            full_name=display_name or None,
            is_superadmin=True,
            is_active=True,
            account_status="active",
        )
        db.add(user)
        db.commit()
        print(f"Админ создан: {email}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
