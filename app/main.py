# app/main.py
try:
    import os, sys

    from starlette.responses import FileResponse
    from starlette.staticfiles import StaticFiles

    from app.routes import auth
    from datetime import timezone, datetime

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from app.database import check_db_connection  # Assure-toi que ce module existe
    from app.config import get_public_path  # Assure-toi que cette fonction est définie dans config.py
except ImportError:
    print("Assurez-vous d'avoir installé les dépendances requises : run 'pip install -r requirements.txt'.")
    raise


# ------------------------------------------------------------
# Vérifie que le répertoire public existe
# ------------------------------------------------------------






def check_public_dir():
    try:
        public_path = get_public_path()
        if public_path is None:
            return FileNotFoundError("Impossible de déterminer le chemin du répertoire public.")
        elif not os.path.isdir(public_path):
            return FileNotFoundError(
                f"Le répertoire public est introuvable à l'emplacement : {public_path}\n"
                f"Contenu du parent ({os.path.dirname(public_path)}) : {os.listdir(os.path.dirname(public_path))}"
            )
        return public_path
    except Exception as e:
        return e


# ------------------------------------------------------------
# Crée l'application FastAPI
# ------------------------------------------------------------
try:
    app = FastAPI(
        title="SafePasseApp SSO",
        description="Serveur SSO pour SafePasseApp - Auth + JWT",
        version="1.0.0",
        debug=True  # ⚠️ active le debug en dev (désactive en prod)
    )

    public_path = check_public_dir()
    app.mount("/public", StaticFiles(directory=public_path), name="public")

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
except Exception as e:
    print(f"Erreur lors de la création de l'application FastAPI: {e}")
    raise


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
