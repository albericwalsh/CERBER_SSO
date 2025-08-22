try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import OperationalError
    from sqlalchemy import text
    import os
except ImportError:
    raise ImportError("Assurez-vous d'avoir installé les dépendances requises : sqlalchemy, pymysql, fastapi, uvicorn.")

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

def get_db():
    """
    Fournit une session SQLAlchemy pour une requête FastAPI et la ferme après usage.
    Utilisation :
        @app.get("/exemple")
        def route(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()