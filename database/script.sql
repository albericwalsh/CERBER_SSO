-- ----- Table des utilisateurs -----
CREATE TABLE CERBER_users
(
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL, -- hash bcrypt/argon2 via password_hash()
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_admin      BOOLEAN   DEFAULT FALSE
);

-- ----- Table des propriétés utilisateur -----
CREATE TABLE CERBER_user_properties
(
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    user_id             INT NOT NULL,
    db_version          VARCHAR(10) DEFAULT '1.0',
    rsa_public_key      TEXT, -- clé publique RSA
    rsa_private_key_enc TEXT, -- clé privée RSA chiffrée
    refresh_token_hash  TEXT, -- hash du refresh token
    FOREIGN KEY (user_id) REFERENCES CERBER_users (id) ON DELETE CASCADE
);
