from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.admin_users import router as admin_users_router
from app.api.routes.agent import router as agent_router
from app.api.routes.auth import router as auth_router
from app.api.routes.data import router as data_router
from app.api.routes.exports import router as exports_router
from app.api.routes.ingest import router as ingest_router
from app.api.routes.members import router as members_router
from app.api.routes.policies import router as policies_router
from app.api.routes.risk_exceptions import router as risk_exceptions_router
from app.api.routes.snapshots import router as snapshots_router
from app.api.routes.twofa import router as twofa_router
from app.core.config import settings

app = FastAPI(title=settings.APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(twofa_router, prefix=settings.API_PREFIX)
app.include_router(data_router, prefix=settings.API_PREFIX)
app.include_router(ingest_router, prefix=settings.API_PREFIX)
app.include_router(agent_router, prefix=settings.API_PREFIX)
app.include_router(exports_router, prefix=settings.API_PREFIX)
app.include_router(snapshots_router, prefix=settings.API_PREFIX)
app.include_router(policies_router, prefix=settings.API_PREFIX)
app.include_router(risk_exceptions_router, prefix=settings.API_PREFIX)
app.include_router(members_router, prefix=settings.API_PREFIX)
app.include_router(admin_users_router, prefix=settings.API_PREFIX)


@app.get("/health")
def health():
    return {"status": "ok"}
