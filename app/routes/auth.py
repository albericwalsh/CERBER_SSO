# app/routes/auth.py
from fastapi import HTTPException, APIRouter, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import select
from starlette import status

from app.database import get_db
from app.models.user import UserProperty, User
from app.schemas.auth import LoginRequest, TokenResponse, RegisterIn, RefreshRequest, UserUpdate, PasswordUpdatePayload
from app.services.auth_service import authenticate_user, create_access_token, create_user, \
    verify_refresh_token, decode_access_token, create_refresh_token, hash_password, store_refresh_token_hash, \
    verify_password
from app.deps.auth import get_current_user, get_current_admin_user  # <-- NEW
from app.utils.logger import logger

router = APIRouter(tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/sso/login")


@router.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        from app.services.auth_service import decode_access_token
        payload = decode_access_token(token)
        return {"message": "Accès autorisé", "user": payload}
    except Exception as e:
        logger.exception("Token invalide: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.post("/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    try:
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
    except Exception as e:
        logger.exception("Erreur lors de l'enregistrement: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    try:
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
    except HTTPException as e:
        logger.exception("Erreur d'authentification: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur lors de la connexion: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


# ---- Route protégée pour tester la dépendance ----
@router.get("/me")
def me(user: User = Depends(get_current_user)):
    try:
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    except Exception as e:
        logger.exception("Erreur lors de la récupération du profil: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.get("/users")
def list_users(db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    """
    Liste tous les utilisateurs (admin uniquement)
    """
    try:
        users = db.query(User).all()
        return [
            {"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin}
            for u in users
        ]
    except Exception as e:
        logger.exception("Erreur lors de la récupération des utilisateurs: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
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
    except HTTPException as e:
        logger.exception("Erreur lors du rafraîchissement du token: %s", str(e.detail))
        raise e


revoked_tokens = set()


@router.post("/logout")
def logout(refresh_token: str):
    """
    Invalide un refresh token
    """
    try:
        revoked_tokens.add(refresh_token)
        return {"msg": "Token invalidé"}
    except Exception as e:
        logger.exception("Erreur lors de la déconnexion: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.get("/users")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    """
    Liste des utilisateurs (admin uniquement)
    """
    try:
        users = db.query(User).all()
        return [
            {"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin}
            for u in users
        ]
    except Exception as e:
        logger.exception("Erreur lors de la récupération des utilisateurs: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.post("/promote/{user_id}")
def make_admin(
        user_id: int,
        db: Session = Depends(get_db),
        current_admin: User = Depends(get_current_admin_user)
):
    """
    Promote un utilisateur en admin.
    Accessible uniquement par un admin existant.
    """
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Utilisateur introuvable"
            )

        if user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="L'utilisateur est déjà admin"
            )

        user.is_admin = True
        db.add(user)
        db.commit()
        db.refresh(user)

        return {"message": f"L'utilisateur {user.username} est maintenant admin"}
    except HTTPException as e:
        logger.exception("Erreur lors de la promotion: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la promotion: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.delete("/promote/{user_id}")
def unmake_admin(
        user_id: int,
        db: Session = Depends(get_db),
        current_admin: User = Depends(get_current_admin_user)
):
    """Retirer le rôle admin à un utilisateur."""
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        if not user.is_admin:
            raise HTTPException(status_code=400, detail="Cet utilisateur n'est pas admin")

        user.is_admin = False
        db.commit()
        db.refresh(user)
        return {"message": f"L'utilisateur {user.username} n'est plus admin"}
    except HTTPException as e:
        logger.exception("Erreur lors de la rétrogradation: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la rétrogradation: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.delete("/{user_id}")
def delete_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_admin: User = Depends(get_current_admin_user)
):
    """Supprimer un utilisateur (action réservée aux admins)."""
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")

        db.delete(user)
        db.commit()
        return {"message": f"Utilisateur {user.username} supprimé avec succès"}
    except HTTPException as e:
        logger.exception("Erreur lors de la suppression: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la suppression: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.put("/users/{user_id}")
def update_user(
        user_id: int,
        payload: UserUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
):
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")

        # --- Si utilisateur courant n'est pas admin ---
        if not current_user.is_admin:
            if current_user.id != user_id:
                raise HTTPException(status_code=403, detail="Vous ne pouvez modifier que votre profil")
            if payload.is_admin is not None and payload.is_admin != user.is_admin:
                raise HTTPException(status_code=403, detail="Vous ne pouvez pas modifier le rôle admin")

        # --- Vérification unicité username ---
        if payload.username and payload.username != user.username:
            exists = db.execute(
                select(User).where(User.username == payload.username)
            ).scalar_one_or_none()
            if exists:
                raise HTTPException(status_code=400, detail="Username déjà utilisé")
            user.username = payload.username

        # --- Vérification unicité email ---
        if payload.email and payload.email != user.email:
            exists = db.execute(
                select(User).where(User.email == payload.email)
            ).scalar_one_or_none()
            if exists:
                raise HTTPException(status_code=400, detail="Email déjà utilisé")
            user.email = payload.email

        if current_user.is_admin and payload.is_admin is not None:
            user.is_admin = payload.is_admin

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
        }
    except HTTPException as e:
        logger.exception("Erreur lors de la mise à jour de l'utilisateur: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la mise à jour de l'utilisateur: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.put("/users/{user_id}/password")
def update_user_password(
        user_id: int,
        payload: PasswordUpdatePayload,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")

        # Si l'utilisateur n'est pas admin
        if not current_user.is_admin:
            # Il ne peut changer que son propre mot de passe
            if current_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Vous ne pouvez modifier que votre propre mot de passe"
                )
            # Vérification de l'ancien mot de passe
            if not payload.old_password or not verify_password(payload.old_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Mot de passe actuel incorrect"
                )

        # Hash du nouveau mot de passe
        user.password_hash = hash_password(payload.new_password)  # <- corrigé ici
        db.add(user)
        db.commit()
        db.refresh(user)

        return {"msg": "Mot de passe mis à jour avec succès"}
    except HTTPException as e:
        logger.exception("Erreur lors de la mise à jour du mot de passe: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la mise à jour du mot de passe: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


@router.get("/validate-token")
def validate_token(request: Request):
    """
    Vérifie si le token Bearer dans les headers est valide.
    """
    try:

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

        token = auth[7:]  # enlever "Bearer "

        try:
            payload = decode_access_token(token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token invalide: {str(e)}")

        return {"valid": True, "user_id": payload.get("id") or payload.get("uid")}
    except HTTPException as e:
        logger.exception("Erreur lors de la validation du token: %s", str(e.detail))
        raise e
    except Exception as e:
        logger.exception("Erreur interne lors de la validation du token: %s", str(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")
