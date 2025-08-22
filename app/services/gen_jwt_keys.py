import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

path = os.getenv("KEY_DIR", "./keys")
key_dir = Path("keys")
key_dir.mkdir(exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem_priv = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pem_pub = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

(os.getenv("JWT_PRIVATE_KEY_FILE", key_dir / "jwt_private.pem")).write_bytes(pem_priv)
(os.getenv("JWT_PUBLIC_KEY_FILE", key_dir / "jwt_public.pem")).write_bytes(pem_pub)

print("✅ Clés générées dans ./keys/")
