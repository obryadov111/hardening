"""Участники организации и их роли. Управляет только администратор организации (superadmin — везде).

Правила:
  * роль — только из ROLES;
  * нельзя удалить или понизить последнего администратора организации: иначе ею некому управлять;
  * изменения касаются только участников этой организации — чужие пользователи дают 404;
  * добавить можно только существующего активного пользователя (учётки создаёт суперадмин).

Ограничение: ответ «пользователь не найден» позволяет администратору организации узнать, есть ли
такой email в системе. Без механизма приглашений этого не избежать; функция доступна только
администраторам организаций.
"""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_org_admin
from app.models.user import User

router = APIRouter(dependencies=[Depends(get_current_user)])

Role = Literal["admin", "auditor", "viewer"]


class MemberIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    role: Role = "viewer"


class RolePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role


def _member_role(db: Session, organization_id: str, user_id: UUID) -> str:
    role = db.execute(
        text("SELECT role FROM user_organizations WHERE organization_id = :org_id AND user_id = :uid"),
        {"org_id": organization_id, "uid": str(user_id)},
    ).scalar()
    if role is None:
        raise HTTPException(status_code=404, detail="Пользователь не состоит в этой организации")
    return role


def _ensure_not_last_admin(db: Session, organization_id: str, user_id: UUID) -> None:
    # FOR UPDATE: два одновременных запроса не должны оба пройти проверку и снять двух последних админов
    admins = db.execute(
        text("SELECT user_id FROM user_organizations WHERE organization_id = :org_id AND role = 'admin' FOR UPDATE"),
        {"org_id": organization_id},
    ).scalars().all()
    if [str(a) for a in admins] == [str(user_id)]:
        raise HTTPException(status_code=409, detail="Нельзя убрать последнего администратора организации")


@router.get("/organizations/{organization_id}/users")
def list_members(organization_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT u.id, u.email, u.display_name, u.full_name, u.is_active, u.account_status, uo.role,
                   uo.created_at AS added_at
            FROM user_organizations uo
            JOIN users u ON u.id = uo.user_id
            WHERE uo.organization_id = :org_id
            ORDER BY uo.role = 'admin' DESC, u.email
        """),
        {"org_id": organization_id},
    ).mappings().all()
    return [dict(row) for row in rows]


@router.post("/organizations/{organization_id}/users", status_code=201)
def add_member(organization_id: str, body: MemberIn, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    user = db.execute(
        text("SELECT id, is_active, account_status FROM users WHERE lower(email) = lower(:email)"),
        {"email": str(body.email)},
    ).mappings().first()
    if user is None or not user["is_active"] or user["account_status"] != "active":
        raise HTTPException(status_code=404, detail="Активный пользователь с таким email не найден")
    exists = db.execute(
        text("SELECT 1 FROM user_organizations WHERE organization_id = :org_id AND user_id = :uid"),
        {"org_id": organization_id, "uid": str(user["id"])},
    ).scalar()
    if exists:
        raise HTTPException(status_code=409, detail="Пользователь уже состоит в организации")
    db.execute(
        text("INSERT INTO user_organizations (user_id, organization_id, role) VALUES (:uid, :org_id, :role)"),
        {"uid": str(user["id"]), "org_id": organization_id, "role": body.role},
    )
    db.commit()
    return {"id": user["id"], "email": str(body.email), "role": body.role}


@router.patch("/organizations/{organization_id}/users/{user_id}")
def change_role(
    organization_id: str, user_id: UUID, body: RolePatch,
    _: User = Depends(require_org_admin), db: Session = Depends(get_db),
):
    current = _member_role(db, organization_id, user_id)
    if current == "admin" and body.role != "admin":
        _ensure_not_last_admin(db, organization_id, user_id)
    db.execute(
        text("UPDATE user_organizations SET role = :role, updated_at = now() WHERE organization_id = :org_id AND user_id = :uid"),
        {"role": body.role, "org_id": organization_id, "uid": str(user_id)},
    )
    db.commit()
    return {"id": user_id, "role": body.role}


@router.delete("/organizations/{organization_id}/users/{user_id}", status_code=204)
def remove_member(organization_id: str, user_id: UUID, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    if _member_role(db, organization_id, user_id) == "admin":
        _ensure_not_last_admin(db, organization_id, user_id)
    db.execute(
        text("DELETE FROM user_organizations WHERE organization_id = :org_id AND user_id = :uid"),
        {"org_id": organization_id, "uid": str(user_id)},
    )
    db.commit()
    return Response(status_code=204)
