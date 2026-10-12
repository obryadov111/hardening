"""Организации-заказчики — заводит суперадмин (аудиторская компания добавляет клиента).

Пользователей в новую организацию добавляют на странице «Пользователи системы» (при создании учётки) или
администратор организации — в её участниках. Ключи агентов для неё выдаются на странице «Агенты».
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.routes.admin_users import require_superadmin
from app.models.organization import ClientOrganization
from app.schemas.data import OrganizationOut

router = APIRouter(prefix="/admin", dependencies=[Depends(require_superadmin)])


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    industry: str | None = Field(default=None, max_length=200)
    country: str | None = Field(default=None, max_length=100)


def _clean(value: str | None) -> str | None:
    return (value or "").strip() or None


@router.post("/organizations", response_model=OrganizationOut, status_code=201)
def create_organization(body: OrganizationCreate, db: Session = Depends(get_db)):
    name = " ".join(body.name.split())
    if not name:
        raise HTTPException(status_code=422, detail="Укажите название организации")
    # Одинаковые названия путали бы выбор организации в интерфейсе — регистр и пробелы не различаются.
    if db.query(ClientOrganization.id).filter(func.lower(ClientOrganization.name) == name.lower()).first():
        raise HTTPException(status_code=409, detail="Организация с таким названием уже есть")

    org = ClientOrganization(name=name, industry=_clean(body.industry), country=_clean(body.country),
                             created_at=datetime.now(UTC))
    db.add(org)
    db.commit()
    db.refresh(org)
    return org
