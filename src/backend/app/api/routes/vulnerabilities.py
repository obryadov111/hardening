"""Потенциальные уязвимости ПО по БДУ ФСТЭК: смотрят участники организации.
Как сопоставляется и считается — app/services/bdu/."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_org_access
from app.models.user import User
from app.services.bdu.matching import organization_vulnerabilities

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{organization_id}/vulnerabilities")
def list_vulnerabilities(
    organization_id: str,
    asset_id: UUID | None = Query(None, description="Только этот актив"),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    return organization_vulnerabilities(db, organization_id, str(asset_id) if asset_id else None)
