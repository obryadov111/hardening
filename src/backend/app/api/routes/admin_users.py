"""Учётные записи системы — только для суперадмина.

Правила:
  * пароль, который задаёт суперадмин (создание, сброс), — временный: пользователь обязан сменить
    его при входе, до этого сервер закрывает остальные ручки (deps.get_current_user). Так
    суперадмин не знает действующего пароля пользователя;
  * сброс пароля отзывает все сессии пользователя (password_changed_at);
  * блокировка действует сразу — get_current_user проверяет статус на каждом запросе;
    «Разблокировать» снимает и временную блокировку после серии неудачных входов (login_guard);
  * нельзя заблокировать или сбросить пароль самому себе (для своего пароля — /auth/change-password);
  * суперадмина через API не создать: это делается командой create_admin на сервере, чтобы
    украденная сессия суперадмина не могла размножить учётки с полными правами.
"""
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.security import hash_password, password_problem
from app.models.user import User

Role = Literal["admin", "auditor", "viewer"]


def require_superadmin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_superadmin:
        raise HTTPException(status_code=403, detail="Только для суперадминистратора")
    return current_user


router = APIRouter(prefix="/admin", dependencies=[Depends(require_superadmin)])


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str
    full_name: str | None = Field(default=None, max_length=200)
    organization_id: UUID | None = None
    role: Role = "viewer"


class PasswordReset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_password: str


def _check_password(password: str, email: str) -> None:
    problem = password_problem(password, email)
    if problem:
        raise HTTPException(status_code=422, detail=f"Пароль не подходит: {problem}")


def _target(db: Session, user_id: UUID, actor: User, action: str) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail=f"Нельзя {action} самому себе")
    return user


@router.get("/users")
def list_users(db: Session = Depends(get_db)):
    rows = db.execute(text("""
        SELECT u.id, u.email, u.full_name, u.display_name, u.is_superadmin, u.is_active, u.account_status,
               u.must_change_password, u.last_login_at, u.created_at,
               CASE WHEN u.locked_until > now() THEN u.locked_until END AS locked_until,
               COALESCE(t.is_enabled, false) AS two_factor_enabled,
               COALESCE(
                   json_agg(json_build_object('id', o.id, 'name', o.name, 'role', uo.role) ORDER BY o.name)
                   FILTER (WHERE o.id IS NOT NULL), '[]'
               ) AS organizations
        FROM users u
        LEFT JOIN user_2fa t ON t.user_id = u.id
        LEFT JOIN user_organizations uo ON uo.user_id = u.id
        LEFT JOIN client_organizations o ON o.id = uo.organization_id
        GROUP BY u.id, t.is_enabled
        ORDER BY u.is_superadmin DESC, u.email
    """)).mappings().all()
    return [dict(row) for row in rows]


@router.post("/users", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db)):
    email = str(body.email).strip().lower()
    _check_password(body.password, email)
    if db.execute(text("SELECT 1 FROM users WHERE lower(email) = :email"), {"email": email}).scalar():
        raise HTTPException(status_code=409, detail="Пользователь с таким email уже есть")
    if body.organization_id and not db.execute(
        text("SELECT 1 FROM client_organizations WHERE id = :id"), {"id": str(body.organization_id)}
    ).scalar():
        raise HTTPException(status_code=404, detail="Организация не найдена")

    name = (body.full_name or "").strip() or None
    now = datetime.now(UTC)
    user = User(
        email=email, password_hash=hash_password(body.password), full_name=name, display_name=name,
        is_superadmin=False, is_active=True, account_status="active",
        must_change_password=True, created_at=now, updated_at=now,
    )
    db.add(user)
    db.flush()
    if body.organization_id:
        db.execute(
            text("INSERT INTO user_organizations (user_id, organization_id, role) VALUES (:uid, :oid, :role)"),
            {"uid": str(user.id), "oid": str(body.organization_id), "role": body.role},
        )
    db.commit()
    return {"id": user.id, "email": user.email, "must_change_password": True}


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: UUID, body: PasswordReset,
    actor: User = Depends(require_superadmin), db: Session = Depends(get_db),
):
    user = _target(db, user_id, actor, "сбросить пароль")
    _check_password(body.new_password, user.email)
    now = datetime.now(UTC)
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = True
    user.password_changed_at = now  # отзывает все текущие сессии пользователя
    user.failed_login_attempts, user.locked_until = 0, None  # новый пароль — с чистого листа
    user.updated_at = now
    db.commit()
    return {"id": user.id, "must_change_password": True}


@router.post("/users/{user_id}/{action}")
def set_blocked(
    user_id: UUID, action: Literal["block", "activate"],
    actor: User = Depends(require_superadmin), db: Session = Depends(get_db),
):
    user = _target(db, user_id, actor, "заблокировать" if action == "block" else "разблокировать")
    now = datetime.now(UTC)
    if action == "block":
        user.account_status, user.blocked_at = "blocked", now
    else:
        user.account_status, user.is_active, user.blocked_at = "active", True, None
        # снимает и временную блокировку после серии неудачных попыток входа
        user.failed_login_attempts, user.locked_until = 0, None
    user.updated_at = now
    db.commit()
    return {"id": user.id, "account_status": user.account_status}
