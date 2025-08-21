# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import OperationalError
    from sqlalchemy import text
except ImportError:
    raise ImportError("Assurez-vous d'avoir installé les dépendances requises : sqlalchemy, pymysql, fastapi, uvicorn.")
import os

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
# Configuration de la base de données
# ------------------------------------------------------------

DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "safepasseapp")

DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create the SQLAlchemy engine and session
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
except Exception as e:
    print(f"Error creating database engine: {e}")
    raise

def check_db_connection():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))  # ⚠️ utiliser text()
        return "ok"
    except OperationalError as e:
        return "error: Database connection failed\n" + str(e)

# ------------------------------------------------------------
# Routes de base
# ------------------------------------------------------------
@app.get("/health")
async def health():
    """Endpoint de santé (pour monitoring / debug)."""
    return {
        "status": "ok",
        "database": check_db_connection()
    }

@app.get("/")
async def root():
    """Page d'accueil simple."""
    return {"message": "🚀 SafePasseApp SSO en ligne !"}



# ------------------------------------------------------------
# Point d'entrée local
# ------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)
