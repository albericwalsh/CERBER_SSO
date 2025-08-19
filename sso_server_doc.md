# 📖 Documentation - SafePasseApp SSO Server

Ce document décrit le fonctionnement et l’utilisation du **serveur SSO** écrit en Python (FastAPI) pour l’application SafePasseApp.

---

## 🚀 Présentation

Le serveur SSO permet :

- L’authentification des utilisateurs (username + mot de passe hashé).
- La génération de **tokens JWT (RS256)** : Access + Refresh.
- L’exposition d’un **endpoint JWKS** pour que les clients puissent vérifier les tokens.
- La récupération des informations de base sur un utilisateur via `/userinfo`.

Les mots de passe utilisateurs sont **hashés avec bcrypt** (via `passlib`) et ne sont jamais stockés en clair.

---

## 📂 Structure du projet

```
sso_server/
│── requirements.txt     # dépendances Python
│── .env.example         # variables d’environnement (à copier en .env)
│── sso_server.py        # code principal FastAPI
```

---

## ⚙️ Installation

### 1. Créer la base SQL

Dans MySQL / phpMyAdmin, exécuter :

```sql
CREATE DATABASE safepasseapp CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE safepasseapp;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE user_properties (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    db_version VARCHAR(10) DEFAULT '1.0',
    rsa_public_key TEXT,
    rsa_private_key_enc TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### 2. Variables d’environnement

Copier `.env.example` → `.env` puis modifier :

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=safepasseapp

ALLOWED_ORIGINS=https://alberic-wds.fr,http://localhost:3000

JWT_ISS=https://alberic-wds.fr
JWT_AUD=safepasseapp-clients
ACCESS_TOKEN_MINUTES=15
REFRESH_TOKEN_DAYS=30
KEY_DIR=./keys
```

### 3. Installer les dépendances

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Lancer le serveur

```bash
uvicorn sso_server:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🔑 Gestion des clés

- Au premier lancement, le serveur génère une paire de clés **RSA 2048 bits** pour signer les JWT.
- Les clés sont stockées dans `KEY_DIR` :
  - `jwt_private.pem` (privée, jamais exposée)
  - `jwt_public.pem` (publique, exposée via JWKS)
  - `kid.txt` (identifiant de la clé pour la rotation)

---

## 📡 Endpoints disponibles

### 📍 Santé

- `GET /health` → `{ "status": "ok" }`

### 📍 Authentification

- `POST /api/v1/sso/register`

  - Body (JSON ou form) : `{ username, email, password }`
  - Retourne infos user (sans token).

- `POST /api/v1/sso/auth`

  - Form data : `username`, `password`
  - Retourne : `{ access_token, refresh_token, expires_in }`

- `POST /api/v1/sso/refresh`

  - Body : `{ refresh_token }`
  - Retourne un nouvel `access_token`.

### 📍 Informations utilisateur

- `GET /api/v1/sso/userinfo`
  - Header : `Authorization: Bearer <access_token>`
  - Retourne `{ id, username, email, properties }`

### 📍 Découverte & clés publiques

- `GET /.well-known/jwks.json` → clé publique au format JWK (pour vérification des JWT).
- `GET /api/v1/sso/.well-known/config` → infos de configuration pour les clients (issuer, audience, endpoints).

---

## 🔐 Sécurité

- Toujours utiliser **HTTPS** en production.
- Les mots de passe sont stockés **hashés (bcrypt)**.
- Les clés RSA serveur doivent être protégées (chmod 600).
- Les **access tokens** expirent rapidement (15 min par défaut).
- Les **refresh tokens** durent plus longtemps (30 jours).
- Rotation des clés conseillée (nouveau `kid` publié, ancien encore dispo tant que des tokens signés avec existent).

---

## 🔮 Améliorations possibles

- Ajouter OAuth2 / OpenID Connect complet (scopes, claims, etc.).
- Stocker des **logs d’audit** (connexion, échecs).
- Gérer la **synchronisation cloud** des coffres-forts `.sfpss` via API.
- Supporter la **revocation des refresh tokens** (liste noire).
- Intégrer avec ton extension web (auth via SSO au lieu d’un login local).

---

## ✅ Conclusion

Ce serveur SSO te fournit une base solide :

- Authentification sécurisée.
- Tokens JWT standardisés.
- Endpoints bien définis.
- Facile à étendre avec d’autres fonctionnalités (sync, OAuth2 complet, etc.).

