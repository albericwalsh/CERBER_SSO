# app/routes/auth.py
from fastapi import HTTPException, APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import UserProperty
from app.schemas.auth import LoginRequest, TokenResponse, RegisterIn, RefreshRequest
from app.services.auth_service import authenticate_user, create_access_token, create_user, \
    verify_refresh_token, create_refresh_token, hash_password, store_refresh_token_hash
from app.deps.auth import get_current_user  # <-- NEW

router = APIRouter(tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/sso/login")


@router.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    from app.services.auth_service import decode_access_token
    payload = decode_access_token(token)
    return {"message": "Accès autorisé", "user": payload}

@router.post("/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    user = create_user(db, payload.username, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=409, detail="Username ou email déjà utilisé")
    # properties est une liste (1..n)
    props = user.properties[0] if user.properties else None
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "properties": {"db_version": props.db_version if props else None}
    }

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.email, payload.password)

    # Génère tokens
    access_token = create_access_token({"sub": user.email, "id": user.id})
    refresh_token_login = create_refresh_token({"sub": user.email, "id": user.id})

    # Stocke le hash du refresh token dans UserProperty
    if user.properties:
        user_prop = user.properties[0]
        user_prop.refresh_token_hash = hash_password(refresh_token_login)
    else:
        user_prop = UserProperty(
            user_id=user.id,
            refresh_token_hash=hash_password(refresh_token_login)
        )
        db.add(user_prop)

    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_login,
        "token_type": "bearer"
    }


# ---- Route protégée pour tester la dépendance ----
@router.get("/me")
def me(current_user = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
    }

@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    # Vérifie le refresh token existant
    user = verify_refresh_token(db, payload.refresh_token)

    # Crée un nouveau access token
    access_token = create_access_token({"sub": user.email, "id": user.id})

    # Rotation: génère un nouveau refresh token
    new_refresh_token = create_refresh_token({"sub": user.email, "id": user.id})

    # Stocke le hash du nouveau refresh token
    store_refresh_token_hash(db, user, new_refresh_token)

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }
