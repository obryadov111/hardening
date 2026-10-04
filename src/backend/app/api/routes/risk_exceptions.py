"""Принятый риск (исключения из оценки): смотрят все участники организации, создаёт и отзывает
администратор организации. Как исключение влияет на оценку — app/services/risk_exceptions.py."""
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_org_access, require_org_admin
from app.models.user import User
from app.services.risk_exceptions import record_org_report, sync_current_state

router = APIRouter(dependencies=[Depends(get_current_user)])

_SELECT = """
    SELECT re.id, re.organization_id, re.asset_id, a.hostname AS asset_hostname, re.check_key, re.reason,
           re.expires_at, re.created_at, cu.email AS created_by_email, re.revoked_at, ru.email AS revoked_by_email,
           CASE
               WHEN re.revoked_at IS NOT NULL THEN 'revoked'
               WHEN re.expires_at IS NOT NULL AND re.expires_at <= now() THEN 'expired'
               ELSE 'active'
           END AS state
    FROM risk_exceptions re
    LEFT JOIN assets a ON a.id = re.asset_id
    LEFT JOIN users cu ON cu.id = re.created_by
    LEFT JOIN users ru ON ru.id = re.revoked_by
"""


class RiskExceptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_key: str = Field(min_length=1, max_length=200)
    asset_id: UUID | None = None  # не указан — на все активы организации
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None

    @field_validator("check_key", "reason")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("поле не может быть пустым")
        return value

    @field_validator("reason")
    @classmethod
    def _meaningful_reason(cls, value: str) -> str:
        # Принятие риска без объяснения ничего не документирует.
        if len(value) < 10:
            raise ValueError("обоснование — не короче 10 символов")
        return value


def _get(db: Session, organization_id: str, exception_id: UUID) -> dict:
    row = db.execute(
        text(_SELECT + " WHERE re.id = :eid AND re.organization_id = :org_id"),
        {"eid": str(exception_id), "org_id": organization_id},
    ).mappings().first()
    if row is None:  # в т.ч. исключение другой организации — не раскрываем, что оно существует
        raise HTTPException(status_code=404, detail="Исключение не найдено")
    return dict(row)


@router.get("/organizations/{organization_id}/risk-exceptions")
def list_risk_exceptions(
    organization_id: str,
    include_inactive: bool = Query(False, description="Показать также отозванные и истёкшие"),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    where = " WHERE re.organization_id = :org_id"
    if not include_inactive:
        where += " AND re.revoked_at IS NULL AND (re.expires_at IS NULL OR re.expires_at > now())"
    rows = db.execute(text(_SELECT + where + " ORDER BY re.created_at DESC"), {"org_id": organization_id}).mappings().all()
    return [dict(row) for row in rows]


@router.post("/organizations/{organization_id}/risk-exceptions", status_code=201)
def create_risk_exception(
    organization_id: str, body: RiskExceptionIn,
    current_user: User = Depends(require_org_admin), db: Session = Depends(get_db),
):
    now = datetime.now(UTC)
    if body.expires_at is not None:
        expires_at = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            raise HTTPException(status_code=422, detail="Срок действия должен быть в будущем")
    asset_id = str(body.asset_id) if body.asset_id else None
    if asset_id is not None:
        in_org = db.execute(
            text("""
                SELECT 1 FROM assets a JOIN environments e ON e.id = a.environment_id
                WHERE a.id = :asset_id AND e.organization_id = :org_id
            """),
            {"asset_id": asset_id, "org_id": organization_id},
        ).scalar()
        if not in_org:
            raise HTTPException(status_code=404, detail="Актив не найден")

    duplicate = db.execute(
        text("""
            SELECT 1 FROM risk_exceptions
            WHERE organization_id = :org_id AND check_key = :check_key
              AND asset_id IS NOT DISTINCT FROM CAST(:asset_id AS uuid)
              AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)
        """),
        {"org_id": organization_id, "check_key": body.check_key, "asset_id": asset_id, "now": now},
    ).scalar()
    if duplicate:
        raise HTTPException(status_code=409, detail="Для этой проверки уже действует исключение")

    exception_id = db.execute(
        text("""
            INSERT INTO risk_exceptions (organization_id, asset_id, check_key, reason, expires_at, created_by, created_at)
            VALUES (:org_id, :asset_id, :check_key, :reason, :expires_at, :user_id, :now)
            RETURNING id
        """),
        {
            "org_id": organization_id, "asset_id": asset_id, "check_key": body.check_key, "reason": body.reason,
            "expires_at": body.expires_at, "user_id": str(current_user.id), "now": now,
        },
    ).scalar()
    sync_current_state(db, organization_id, now)
    record_org_report(db, organization_id, now)
    db.commit()
    return _get(db, organization_id, exception_id)


@router.delete("/organizations/{organization_id}/risk-exceptions/{exception_id}", status_code=204)
def revoke_risk_exception(
    organization_id: str, exception_id: UUID,
    current_user: User = Depends(require_org_admin), db: Session = Depends(get_db),
):
    """Отзыв, а не удаление: решение остаётся в истории (и на него ссылаются старые снимки)."""
    existing = _get(db, organization_id, exception_id)
    if existing["revoked_at"] is None:
        now = datetime.now(UTC)
        db.execute(
            text("UPDATE risk_exceptions SET revoked_at = :now, revoked_by = :user_id WHERE id = :eid"),
            {"now": now, "user_id": str(current_user.id), "eid": str(exception_id)},
        )
        sync_current_state(db, organization_id, now)
        record_org_report(db, organization_id, now)
        db.commit()
    return Response(status_code=204)
