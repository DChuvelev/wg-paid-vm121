from fastapi import FastAPI
from sqlalchemy import text

from app.config import settings
from app.db.session import engine
from app.api.admin import router as admin_router
from app.api.dev import router as dev_router
from app.api.agent import router as agent_router

app = FastAPI(title="WG Access Backend", version="0.0.3")

app.include_router(admin_router)
app.include_router(dev_router)
app.include_router(agent_router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "wg-access-backend",
        "environment": settings.environment,
    }


@app.get("/health/db")
def health_db():
    with engine.connect() as conn:
        value = conn.execute(text("select 1")).scalar_one()
    return {
        "status": "ok",
        "db": value,
    }
