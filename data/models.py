from .db import Base, AsyncSession, SessionLocal
from typing import List
from sqlalchemy.exc import IntegrityError
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    ForeignKey,
    DateTime,
    func,
    Enum,
    select,
    Boolean
)
from sqlalchemy.orm import relationship, selectinload
#from .schemas import RoleResponseSchema, QuestionSchema
import enum
import os, dotenv
from pathlib import Path
import json
import asyncio
import bcrypt
from datetime import datetime, timedelta, timezone
import secrets


# class User(Base):
#     __tablename__ = "users"

#     id = Column(Integer, primary_key=True, index=True)
#     user_name = Column(String, nullable=False, unique=True)
#     password_hash = Column(String, nullable=False)
#     created_at = Column(DateTime(timezone=True), nullable=False)

#     device = relationship("Device", backref="device")

# class Device(Base):
#     __tablename__ = "devices"

#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
#     device_name = Column(String, nullable=True)
#     public_key = Column(String, nullable=False)
#     last_used = Column(DateTime(timezone=True), nullable=True)
#     created_at = Column(DateTime(timezone=True), nullable=False)
#     revoked = Column(Boolean, default=False)

#     user = relationship("User", backref="user")

# class Token(Base):
#     __tablename__ = "tokens"

#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
#     device_id = Column(Integer, ForeignKey("device.id", ondelete="CASCADE"), nullable=False)
#     token  = Column(String, nullable=False)
#     expires_at = Column(DateTime(timezone=True), nullable=False)
#     used = Column(Boolean, default=False)
#     created_at = Column(DateTime(timezone=True), nullable=False)

#     user = relationship("User", backref="user")
#     device = relationship("Device", backref="device")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)

    devices = relationship("Device", back_populates="user")
    tokens = relationship("Token", back_populates="user")

    @classmethod
    async def create_user(cls, db: AsyncSession, username: str, password: str):
        # Ensure username is unique
        existing = await db.execute(select(cls).where(cls.user_name == username))
        if existing.scalar():
            raise ValueError("Username already exists")

        # Hash the password
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Create user instance
        user = cls(
            user_name=username,
            password_hash=hashed_pw,
            created_at=datetime.now(timezone.utc)
        )

        db.add(user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Username already exists")
        await db.flush()  # ensures user.id exists
        result = await db.execute(
            select(cls).where(cls.id == int(user.id))
        )
        inserted_user = result.scalar_one()
        return inserted_user
    
    @staticmethod
    def generate_registration_challenge():
        # Random token the device will use for registration
        return secrets.token_urlsafe(32)

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    device_name = Column(String, nullable=True)
    public_key = Column(String, nullable=False, unique=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)

    user = relationship("User", back_populates="devices")


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    token = Column(String, nullable=False, unique=True, index=True)
    token_type = Column(String, nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="tokens")

    @classmethod
    async def create_challenge(
        cls,
        db: AsyncSession,
        user_id: int,
        token_type: str = "registration",
        expires_minutes: int = 5
    ):
        challenge = secrets.token_urlsafe(32)

        token = cls(
            user_id=user_id,
            token=challenge,
            token_type=token_type,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
            created_at=datetime.now(timezone.utc),
            used=False
        )

        db.add(token)
        await db.commit()
        await db.refresh(token)

        return token

    @classmethod
    async def get_valid_token(
        cls,
        db: AsyncSession,
        token_value: str,
        token_type: str
    ):
        result = await db.execute(
            select(cls).where(
                cls.token == token_value,
                cls.token_type == token_type,
                cls.used == False,
                cls.expires_at > datetime.now(timezone.utc)
            )
        )

        token = result.scalar_one_or_none()

        if not token:
            raise ValueError("Invalid or expired token")

        return token


if __name__ == "__main__":
    pass



