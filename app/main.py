from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings

from app.api.rule_control import router as rule_control_router
from app.api.intelligence import router as intelligence_router
from app.api.graph import router as graph_router

from app.api.soc_dashboard import router as soc_dashboard_router
from app.api.soc_alerts import router as soc_alerts_router
from app.api.soc_graph import router as soc_graph_router
from app.api.soc_investigation import router as soc_investigation_router
from app.api.soc_actions import router as soc_actions_router
from app.api.response import router as response_router
from app.api.simulation import router as simulation_router
from app.api.reports import router as reports_router

BASE_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = BASE_DIR / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Cyber Sentinel XDR — "
        "Defensive Security Operations Platform"
    ),
)


# =========================================================
# STATIC FILES
# =========================================================

if ASSETS_DIR.exists():
    app.mount(
        "/assets",
        StaticFiles(
            directory=str(ASSETS_DIR)
        ),
        name="assets",
    )


# =========================================================
# FRONTEND
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    index_file = FRONTEND_DIR / "index.html"

    if index_file.exists():
        return index_file.read_text(
            encoding="utf-8"
        )

    return """
    <html>
        <body>
            <h1>Cyber Sentinel XDR</h1>
            <p>Frontend not found.</p>
        </body>
    </html>
    """


@app.get("/soc", response_class=HTMLResponse)
async def soc_dashboard():
    soc_file = FRONTEND_DIR / "soc.html"

    if soc_file.exists():
        return soc_file.read_text(
            encoding="utf-8"
        )

    return """
    <html>
        <body>
            <h1>Cyber Sentinel XDR SOC</h1>
            <p>SOC dashboard not found.</p>
        </body>
    </html>
    """


# =========================================================
# HEALTH
# =========================================================

@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "mode": settings.APP_ENV,
    }


# =========================================================
# CORE / INTELLIGENCE / GRAPH ROUTES
# =========================================================

app.include_router(
    rule_control_router
)

app.include_router(
    intelligence_router
)

app.include_router(
    graph_router
)


# =========================================================
# SOC / XDR ROUTES
# =========================================================

app.include_router(
    soc_dashboard_router
)

app.include_router(
    soc_alerts_router
)

app.include_router(
    soc_graph_router
)

app.include_router(soc_actions_router)
app.include_router(response_router)
app.include_router(simulation_router)
app.include_router(reports_router)

app.include_router(
    soc_investigation_router
)


# =========================================================
# STARTUP / SHUTDOWN
# =========================================================


@app.on_event("startup")
async def startup_event():
    print(
        f"{settings.APP_NAME} "
        f"v{settings.APP_VERSION} "
        f"started in {settings.APP_ENV} mode"
    )


@app.on_event("shutdown")
async def shutdown_event():
    print(
        f"{settings.APP_NAME} shutting down"
    )
