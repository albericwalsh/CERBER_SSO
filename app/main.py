#!/usr/bin/env python3
"""
SafePasseApp - Minimal SSO server (FastAPI)
- Auth with username/password stored in MySQL (hash via bcrypt)
- Issues JWT (RS256) access + refresh tokens
- Exposes /.well-known/jwks.json so clients can verify tokens
- Userinfo endpoint to fetch basic profile + user_properties
"""
import os
import json
import base64
import datetime as dt
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Text, ForeignKey, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
from passlib.context import CryptContext
import jwt
from jwt import PyJWK
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from fastapi import FastAPI
from a2wsgi import ASGIMiddleware

# -------------------- Configuration --------------------
load_dotenv()  # read .env if present

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "safepasseapp")

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")]
JWT_ISS = os.getenv("JWT_ISS", "http://localhost:8000")
JWT_AUD = os.getenv("JWT_AUD", "safepasseapp-clients")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "30"))
KEY_DIR = os.getenv("KEY_DIR", "./keys")

os.makedirs(KEY_DIR, exist_ok=True)

PRIV_KEY_PATH = os.path.join(KEY_DIR, "jwt_private.pem")
PUB_KEY_PATH = os.path.join(KEY_DIR, "jwt_public.pem")
KID_PATH = os.path.join(KEY_DIR, "kid.txt")

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------- Database Models --------------------
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    properties: Mapped["UserProperties"] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan")

class UserProperties(Base):
    __tablename__ = "user_properties"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    db_version: Mapped[Optional[str]] = mapped_column(String(10), default="1.0")
    rsa_public_key: Mapped[Optional[str]] = mapped_column(Text)
    rsa_private_key_enc: Mapped[Optional[str]] = mapped_column(Text)
    user: Mapped[User] = relationship(back_populates="properties")

# SQLAlchemy engine/session
engine = create_engine(
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4",
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# -------------------- Keypair for JWT (Server keys) --------------------
def ensure_server_keys():
    # Generate server-level RSA keypair once (for signing JWT)
    if not (os.path.exists(PRIV_KEY_PATH) and os.path.exists(PUB_KEY_PATH)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(PRIV_KEY_PATH, "wb") as f:
            f.write(priv_pem)
        with open(PUB_KEY_PATH, "wb") as f:
            f.write(pub_pem)

    # Simple KID (key id) derived from public key fingerprint
    if not os.path.exists(KID_PATH):
        with open(PUB_KEY_PATH, "rb") as f:
            pub = f.read()
        kid = base64.urlsafe_b64encode(pub[:16]).decode().rstrip("=")
        with open(KID_PATH, "w") as f:
            f.write(kid)

def load_keys():
    ensure_server_keys()
    with open(PRIV_KEY_PATH, "rb") as f:
        priv = f.read()
    with open(PUB_KEY_PATH, "rb") as f:
        pub = f.read()
    with open(KID_PATH, "r") as f:
        kid = f.read().strip()
    return priv, pub, kid

PRIV_KEY_PEM, PUB_KEY_PEM, KID = load_keys()

# -------------------- Pydantic Schemas --------------------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str
    password: str = Field(min_length=8, max_length=128)

class TokenOut(BaseModel):
    token_type: str = "Bearer"
    access_token: str
    expires_in: int
    refresh_token: Optional[str] = None

class RefreshIn(BaseModel):
    refresh_token: str

class UserInfoOut(BaseModel):
    id: int
    username: str
    email: str
    properties: Optional[dict] = None

# -------------------- Utilities --------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(sub: str, username: str, scopes: Optional[List[str]] = None, minutes: int = ACCESS_TOKEN_MINUTES):
    now = dt.datetime.utcnow()
    payload = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "sub": sub,
        "preferred_username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=minutes)).timestamp()),
        "scope": " ".join(scopes or []),
    }
    token = jwt.encode(payload, PRIV_KEY_PEM, algorithm="RS256", headers={"kid": KID})
    return token

def create_refresh_token(sub: str, days: int = REFRESH_TOKEN_DAYS):
    now = dt.datetime.utcnow()
    payload = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "sub": sub,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(days=days)).timestamp()),
    }
    token = jwt.encode(payload, PRIV_KEY_PEM, algorithm="RS256", headers={"kid": KID})
    return token

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

# -------------------- FastAPI App --------------------
app = FastAPI(title="SafePasseApp SSO", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    # Ensure tables exist (no destructive migration)
    Base.metadata.create_all(engine)

@app.get("/health")
def health():
    return {"status": "ok"}

# ---------- Auth endpoints ----------
@app.post("/api/v1/sso/register", response_model=UserInfoOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    # check uniqueness
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status_code=409, detail="Username or email already exists")
    user = User(username=payload.username, email=payload.email, password_hash=hash_password(payload.password))
    db.add(user)
    db.flush()  # get user.id
    props = UserProperties(user_id=user.id, db_version="1.0")
    db.add(props)
    db.commit()
    db.refresh(user)
    return UserInfoOut(id=user.id, username=user.username, email=user.email, properties={"db_version": props.db_version})

@app.post("/api/v1/sso/auth", response_model=TokenOut)
def auth(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2 form expects fields: username, password
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access = create_access_token(str(user.id), user.username, scopes=["basic"])
    refresh = create_refresh_token(str(user.id))
    return TokenOut(access_token=access, refresh_token=refresh, expires_in=ACCESS_TOKEN_MINUTES * 60)

@app.post("/api/v1/sso/refresh", response_model=TokenOut)
def refresh_token(payload: RefreshIn):
    try:
        decoded = jwt.decode(payload.refresh_token, PUB_KEY_PEM, algorithms=["RS256"], audience=JWT_AUD, issuer=JWT_ISS)
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Not a refresh token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    sub = decoded["sub"]
    username = decoded.get("preferred_username", "")
    access = create_access_token(sub, username, scopes=["basic"])
    return TokenOut(access_token=access, expires_in=ACCESS_TOKEN_MINUTES * 60)

@app.get("/api/v1/sso/userinfo", response_model=UserInfoOut)
def userinfo(authorization: Optional[str] = None, db: Session = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        decoded = jwt.decode(token, PUB_KEY_PEM, algorithms=["RS256"], audience=JWT_AUD, issuer=JWT_ISS)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = int(decoded["sub"])
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    props = user.properties
    return UserInfoOut(
        id=user.id,
        username=user.username,
        email=user.email,
        properties={
            "db_version": props.db_version if props else None,
            "rsa_public_key": props.rsa_public_key if props else None,
        } if props else None
    )

# ---------- JWKS (public keys) ----------
def pem_to_jwk(pub_pem: bytes, kid: str) -> dict:
    # Use PyJWT to parse and export JWK
    jwk_obj: PyJWK = PyJWK.from_pem(pub_pem, alg="RS256")
    jwk = jwk_obj.to_dict()
    jwk["use"] = "sig"
    jwk["kid"] = kid
    return jwk

@app.get("/.well-known/jwks.json")
def jwks():
    return {"keys": [pem_to_jwk(PUB_KEY_PEM, KID)]}

# ---------- Minimal client hint (for JS frontends) ----------
@app.get("/api/v1/sso/.well-known/config")
def client_config():
    return {
        "issuer": JWT_ISS,
        "audience": JWT_AUD,
        "token_endpoint": "/api/v1/sso/auth",
        "userinfo_endpoint": "/api/v1/sso/userinfo",
        "jwks_uri": "/.well-known/jwks.json",
    }

# ---------- JWKS, client config, etc. (inchangé) ----------

# -------------------- Passenger WSGI --------------------
passenger_app = ASGIMiddleware(app)

# Le bloc __main__ pour dev local (facultatif)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)


