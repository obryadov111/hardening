"""Реестр политик организации: смотрят все участники, меняет администратор организации
(право manage_policies в /my-role)."""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_org_access, require_org_admin
from app.models.user import User

router = APIRouter(dependencies=[Depends(get_current_user)])

PolicyStatus = Literal["draft", "active", "review", "archived"]  # как CHECK в таблице policies

_COLUMNS = "id, organization_id, name, description, scope, status, owner_name, source, created_at, updated_at"


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    scope: str | None = Field(default=None, max_length=500)
    status: PolicyStatus = "draft"
    owner_name: str | None = Field(default=None, max_length=200)
    source: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def _name(cls, name: str) -> str:
        name = name.strip()
        if not name:
            raise ValueError("название не может быть пустым")
        return name

    _optional = field_validator("description", "scope", "owner_name", "source")(_clean)


class PolicyPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    scope: str | None = Field(default=None, max_length=500)
    status: PolicyStatus | None = None
    owner_name: str | None = Field(default=None, max_length=200)
    source: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def _name(cls, name: str | None) -> str | None:
        if name is not None and not name.strip():
            raise ValueError("название не может быть пустым")
        return name.strip() if name else name

    _optional = field_validator("description", "scope", "owner_name", "source")(_clean)


def _get_policy(db: Session, organization_id: str, policy_id: UUID) -> dict:
    row = db.execute(
        text(f"SELECT {_COLUMNS} FROM policies WHERE id = :pid AND organization_id = :org_id"),
        {"pid": str(policy_id), "org_id": organization_id},
    ).mappings().first()
    if row is None:  # в т.ч. политика другой организации — не раскрываем, что она существует
        raise HTTPException(status_code=404, detail="Политика не найдена")
    return dict(row)


@router.get("/organizations/{organization_id}/policies")
def list_policies(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text(f"SELECT {_COLUMNS} FROM policies WHERE organization_id = :org_id ORDER BY updated_at DESC, name"),
        {"org_id": organization_id},
    ).mappings().all()
    return [dict(row) for row in rows]


@router.post("/organizations/{organization_id}/policies", status_code=201)
def create_policy(organization_id: str, body: PolicyIn, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    row = db.execute(
        text(f"""
            INSERT INTO policies (organization_id, name, description, scope, status, owner_name, source)
            VALUES (:org_id, :name, :description, :scope, :status, :owner_name, :source)
            RETURNING {_COLUMNS}
        """),
        {"org_id": organization_id, **body.model_dump()},
    ).mappings().first()
    db.commit()
    return dict(row)


@router.patch("/organizations/{organization_id}/policies/{policy_id}")
def update_policy(
    organization_id: str, policy_id: UUID, body: PolicyPatch,
    _: User = Depends(require_org_admin), db: Session = Depends(get_db),
):
    _get_policy(db, organization_id, policy_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("name", "") is None:
        raise HTTPException(status_code=422, detail="название не может быть пустым")
    if not changes:
        return _get_policy(db, organization_id, policy_id)
    # Имена колонок — только из полей модели (extra=forbid), значения — параметрами.
    assignments = ", ".join(f"{column} = :{column}" for column in changes)
    row = db.execute(
        text(f"UPDATE policies SET {assignments}, updated_at = now() WHERE id = :pid AND organization_id = :org_id RETURNING {_COLUMNS}"),
        {**changes, "pid": str(policy_id), "org_id": organization_id},
    ).mappings().first()
    db.commit()
    return dict(row)


@router.delete("/organizations/{organization_id}/policies/{policy_id}", status_code=204)
def delete_policy(organization_id: str, policy_id: UUID, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    _get_policy(db, organization_id, policy_id)
    db.execute(text("DELETE FROM policies WHERE id = :pid AND organization_id = :org_id"), {"pid": str(policy_id), "org_id": organization_id})
    db.commit()
    return Response(status_code=204)
