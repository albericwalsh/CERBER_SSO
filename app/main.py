# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ------------------------------------------------------------
# Crée l'application FastAPI
# ------------------------------------------------------------
app = FastAPI(
    title="SafePasseApp SSO",
    description="Serveur SSO pour SafePasseApp - Auth + JWT",
    version="1.0.0",
    debug=True  # ⚠️ active le debug en dev (désactive en prod)
)

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
    """Endpoint de santé (pour monitoring / debug)."""
    return {"status": "ok"}

@app.get("/")
async def root():
    """Page d'accueil simple."""
    return {"message": "🚀 SafePasseApp SSO en ligne !"}

# Exemple route de test
@app.get("/hello/{name}")
async def hello(name: str):
    return {"message": f"Hello {name} 👋"}

# ------------------------------------------------------------
# Point d'entrée local
# ------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
