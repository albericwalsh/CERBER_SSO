from sqlalchemy import Column, Integer, String, ForeignKey, TIMESTAMP, Text, func, Boolean
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "CERBER_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    is_admin = Column(Boolean, default=False)  # ✅ nouveau champ

    properties = relationship("UserProperty", back_populates="user", cascade="all, delete-orphan")
    # app/models/user.py


class UserProperty(Base):
    __tablename__ = "CERBER_user_properties"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("CERBER_users.id", ondelete="CASCADE"), nullable=False)
    db_version = Column(String(10), default="1.0")
    rsa_public_key = Column(Text)
    rsa_private_key_enc = Column(Text)
    refresh_token_hash = Column(String(255))  # <-- ajouté

    user = relationship("User", back_populates="properties")