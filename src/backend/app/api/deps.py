from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_agent_api_key
from app.db.session import SessionLocal
from app.models.user import User
from app.services.packs.registry import PackRegistry, load_registry

bearer_scheme = HTTPBearer()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@lru_cache
def _load_default_registry() -> PackRegistry:
    directory = Path(settings.PACKS_DIR) if settings.PACKS_DIR else Path(__file__).resolve().parents[1] / "packs"
    return load_registry(directory)


def get_pack_registry() -> PackRegistry:
    """Реестр паков, загруженный один раз при первом обращении. Битый пак роняет запрос явной
    ошибкой с именем файла, а не молча пропускается (иначе платформа «тихо» осталась бы без проверок)."""
    return _load_default_registry()


def get_current_user_allow_password_change(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Пользователь по токену, в т.ч. с временным паролем. Только для /auth/me и смены пароля;
    остальные ручки — через get_current_user."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        subject = payload.get("sub")
        if not subject:
            raise ValueError("missing sub")
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный токен") from exc

    user = db.query(User).filter(User.id == subject).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пользователь не найден")
    # Смена или сброс пароля отзывает все выданные раньше токены. Токен без iat выдан до появления
    # этой проверки: для пользователя, у которого пароль с тех пор менялся, он тоже недействителен.
    if user.password_changed_at is not None:
        issued_at = payload.get("iat")
        if issued_at is None or float(issued_at) < user.password_changed_at.timestamp():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия завершена: пароль был изменён")
    if not user.is_active or user.account_status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Пользователь заблокирован")

    return user


PASSWORD_CHANGE_REQUIRED = "Нужно сменить временный пароль"


def get_current_user(user: User = Depends(get_current_user_allow_password_change)) -> User:
    """Пользователь по токену. С временным паролем (задан администратором) доступ закрыт на сервере,
    пока пароль не сменён, — а не только скрыт в интерфейсе."""
    if user.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PASSWORD_CHANGE_REQUIRED)
    return user


def get_user_role_in_org(db: Session, user: User, organization_id: str) -> str | None:
    """Роль пользователя в организации: superadmin трактуется как admin везде,
    иначе — членство в user_organizations. None = нет доступа."""
    if user.is_superadmin:
        return "admin"
    return db.execute(
        text("SELECT role FROM user_organizations WHERE user_id = :user_id AND organization_id = :org_id"),
        {"user_id": str(user.id), "org_id": organization_id},
    ).scalar()


def require_org_access(organization_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    """Dependency: 404 если организации не существует, 403 если у пользователя нет к ней доступа.
    Использовать на всех ручках вида /organizations/{organization_id}/..."""
    org_exists = db.execute(
        text("SELECT 1 FROM client_organizations WHERE id = :org_id"),
        {"org_id": organization_id},
    ).scalar()
    if not org_exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Организация не найдена")

    role = get_user_role_in_org(db, current_user, organization_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет доступа к этой организации")

    return current_user


def require_org_admin(organization_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    """Dependency: как require_org_access, но нужна роль admin в организации (superadmin — везде).
    Для изменений: участники организации, политики."""
    require_org_access(organization_id, current_user, db)
    if get_user_role_in_org(db, current_user, organization_id) != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нужна роль администратора организации")
    return current_user


def get_accessible_org_ids(db: Session, user: User) -> list[str] | None:
    """Список organization_id, доступных пользователю. None = доступны все (superadmin)."""
    if user.is_superadmin:
        return None
    rows = db.execute(
        text("SELECT organization_id FROM user_organizations WHERE user_id = :user_id"),
        {"user_id": str(user.id)},
    ).scalars().all()
    return [str(r) for r in rows]


def get_agent_organization_id(
    x_agent_api_key: str | None = Header(default=None, alias="X-Agent-Api-Key"),
    db: Session = Depends(get_db),
) -> str:
    """Аутентификация агента-сборщика по статичному ключу (см. app/commands/create_agent_key.py).
    Organization_id берётся из самого ключа, а не из тела запроса — агент не может
    выдать себя за другую организацию, даже подделав payload."""
    if not x_agent_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Отсутствует X-Agent-Api-Key")

    key_hash = hash_agent_api_key(x_agent_api_key)
    row = db.execute(
        text("SELECT id, organization_id, is_active FROM agent_api_keys WHERE key_hash = :key_hash"),
        {"key_hash": key_hash},
    ).mappings().first()

    if not row or not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный ключ агента")

    db.execute(
        text("UPDATE agent_api_keys SET last_used_at = :now WHERE id = :id"),
        {"now": datetime.now(UTC), "id": row["id"]},
    )
    db.commit()

    return str(row["organization_id"])