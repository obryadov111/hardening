"""Покрытие методики анализа защищённости ФСТЭК от 25.11.2025 по пунктам (app/services/fstec)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_pack_registry, require_org_access
from app.models.user import User
from app.services.fstec.coverage import organization_coverage
from app.services.packs.registry import PackRegistry

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{organization_id}/fstec-coverage")
def fstec_coverage(
    organization_id: str,
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    return organization_coverage(db, organization_id, registry)
