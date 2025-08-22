# app/main.py
import os

from starlette.responses import FileResponse
from starlette.staticfiles import StaticFiles

from app.routes import auth
from datetime import timezone, datetime

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from app.database import check_db_connection  # Assure-toi que ce module existe
except ImportError:
    raise ImportError("Assurez-vous d'avoir installé les dépendances requises : fastapi, uvicorn.")


# ------------------------------------------------------------
# Crée l'application FastAPI
# ------------------------------------------------------------
app = FastAPI(
    title="SafePasseApp SSO",
    description="Serveur SSO pour SafePasseApp - Auth + JWT",
    version="1.0.0",
    debug=True  # ⚠️ active le debug en dev (désactive en prod)
)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # remonte d’un niveau
app.mount("/public", StaticFiles(directory=os.path.join(BASE_DIR, "public")), name="public")

# ------------------------------------------------------------
# Middleware CORS (si tu appelles l'API depuis un front séparé)
# ------------------------------------------------------------
origins = [
    "http://localhost:3000",  # ton front local
    "https://alberic-wds.fr",  # ton domaine
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# Routes de base
# ------------------------------------------------------------
@app.get("/health")
async def health():
    db_status = check_db_connection()
    status_ok = db_status == "ok"
    return {
        "status": "ok" if status_ok else "error",
        "database": db_status,
        "uptime": datetime.now(timezone.utc).isoformat()
    }


# Simple page d'accueil
@app.get("/")
async def root():
    """Page d'accueil simple."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "../public/index.html"))

# Dashboard admin (exemple)
@app.get("/admin")
async def admin_dashboard():
    """Page d'administration simple."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "../public/admin.html"))

# Dashboard user (exemple)
@app.get("/dashboard")
async def user_dashboard():
    """Page utilisateur simple."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "../public/dashboard.html"))

# ⚡ Ici tu ajoutes tes routes au FastAPI app
app.include_router(auth.router, prefix="/api/v1/sso")

# ------------------------------------------------------------
# Point d'entrée local
# ------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)
