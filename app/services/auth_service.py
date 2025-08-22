# app/services/auth_service.py
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, status
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.models.user import User, UserProperty
from app.utils.logger import logger


# ---- Environment variables ----
KEY_DIR = Path(os.getenv("KEY_DIR", "./keys"))
PRIVATE_KEY_PATH = KEY_DIR / "jwt_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "jwt_public.pem"
OLD_PUBLIC_KEY = Path(KEY_DIR) / "jwt_public_old.pem"
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "30"))
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
JWT_ISS = os.getenv("JWT_ISS", "http://localhost:8000")
JWT_AUD = os.getenv("JWT_AUD", "safepasseapp-clients")

# ---- RSA key generation and loading ----

def ensure_keys_exist():
    """Génère les clés RSA si elles n'existent pas."""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        print("🔑 Génération des clés RSA...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Sauvegarde private.pem
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Sauvegarde public.pem
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def load_keys():
    global PRIVATE_KEY, PUBLIC_KEY, OLD_PUBLIC_KEY
    PRIVATE_KEY = Path(KEY_DIR) / "jwt_private.pem"
    PUBLIC_KEY = Path(KEY_DIR) / "jwt_public.pem"
    OLD_PUBLIC_KEY = Path(KEY_DIR) / "jwt_public_old.pem"  # si existante

# Appelé automatiquement au démarrage
ensure_keys_exist()

# Charger les clés en mémoire
with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = f.read()

with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = f.read()

ALGORITHM = "RS256"

# ---- Password hashing ----
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

# ---- JWT / RS256 config ----
# Datetime aware en UTC
def make_now_and_exp(minutes: int = 0, days: int = 0) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)  # ✅ datetime aware en UTC
    exp = now + timedelta(minutes=minutes, days=days)
    return now, exp

# Cache en mémoire après première lecture
_PRIVATE_KEY = None
_PUBLIC_KEY = None

def _load_private_key() -> str:
    global _PRIVATE_KEY
    if _PRIVATE_KEY is None:
        try:
            _PRIVATE_KEY = PRIVATE_KEY_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise RuntimeError(f"Clé privée introuvable: {PRIVATE_KEY_PATH}")
    return _PRIVATE_KEY

def _load_public_key() -> str:
    global _PUBLIC_KEY
    if _PUBLIC_KEY is None:
        try:
            _PUBLIC_KEY = PUBLIC_KEY_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise RuntimeError(f"Clé publique introuvable: {PUBLIC_KEY_PATH}")
    return _PUBLIC_KEY

def create_access_token(data: dict) -> str:
    """
    data attend au minimum {"sub": <email>, "id": <user_id>}
    """
    now, exp = make_now_and_exp(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        **data,
    }
    token = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISS,
            audience=JWT_AUD,
        )
        return payload
    except jwt.InvalidSignatureError:
        if OLD_PUBLIC_KEY.exists():
            payload = jwt.decode(
                token,
                OLD_PUBLIC_KEY,
                algorithms=[ALGORITHM],
                issuer=JWT_ISS,
                audience=JWT_AUD,
            )
            return payload
        else:
            raise HTTPException(status_code=401, detail="Token invalide")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expiré")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Audience invalide")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Issuer invalide")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")

def hash_refresh_token(token: str) -> str:
    """Hash du refresh token pour stockage sécurisé"""
    return pwd_ctx.hash(token)

def create_refresh_token(data: dict) -> str:
    now, exp = make_now_and_exp(days=REFRESH_TOKEN_DAYS)
    to_encode = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        **data,
    }
    token = jwt.encode(to_encode, _load_private_key(), algorithm=ALGORITHM)
    return token

# Refresh token
def verify_refresh_token(db: Session, token: str) -> User:
    try:
        payload = jwt.decode(token, _load_public_key(), algorithms=[ALGORITHM], issuer=JWT_ISS, audience=JWT_AUD)
        user_id = payload["id"]
    except jwt.PyJWTError:
        logger.warning("Refresh token invalide détecté")
        raise HTTPException(status_code=401, detail="Refresh token invalide")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.warning("Refresh token pour user_id=%s non trouvé", user_id)
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    props = user.properties[0]
    if not props.refresh_token_hash or not pwd_ctx.verify(token, props.refresh_token_hash):
        logger.warning("Refresh token révoqué pour user_id=%d", user_id)
        raise HTTPException(status_code=401, detail="Refresh token invalide ou révoqué")

    logger.info("Refresh token validé pour user_id=%d", user_id)
    return user

def store_refresh_token_hash(db: Session, user, refresh_token: str):
    """Stocke le hash du refresh token dans les propriétés utilisateur."""
    props = user.properties[0]
    props.refresh_token_hash = pwd_ctx.hash(refresh_token)
    db.add(props)
    db.commit()

# ---- CRUD/Auth ----
# Création d'utilisateur
def create_user(db: Session, username: str, email: str, password: str):
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        logger.warning("Tentative de création utilisateur existant: %s / %s", username, email)
        return None
    user = User(username=username, email=email, password_hash=hash_password(password))
    db.add(user)
    db.flush()
    db.add(UserProperty(user_id=user.id, db_version="1.0"))
    db.commit()
    db.refresh(user)
    logger.info("Nouvel utilisateur créé: user_id=%d email=%s", user.id, email)
    return user

# Login
def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        logger.warning("Login échoué pour email=%s", email)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    logger.info("Login réussi pour user_id=%d email=%s", user.id, user.email)
    return user
