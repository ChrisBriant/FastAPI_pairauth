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
from services.auth_exceptions import TokenExpired, TokenNotFound, TokenUsed, DeviceAlreadyRegistered
from services.auth import decode_public_key


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
    terms_accepted = Column(Boolean, nullable=False, default=False)

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

    def verify_password(self, password: str) -> bool:
        """
        Check if the provided password matches the stored hash.
        """
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: int):
        """
        Retrieve a user by ID with devices and tokens loaded.
        Returns the User object or None if not found.
        """
        result = await db.execute(
            select(cls)
            .options(
                selectinload(cls.devices),
                selectinload(cls.tokens)
            )
            .where(cls.id == user_id)
        )
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_user_name(cls, db: AsyncSession, user_name: str):
        """
        Retrieve a user by username with devices and tokens loaded.
        Returns the User object or None if not found.
        """
        result = await db.execute(
            select(cls)
            .options(
                selectinload(cls.devices),
                selectinload(cls.tokens)
            )
            .where(cls.user_name == user_name)
        )
        return result.scalar_one_or_none()

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

    @classmethod
    async def is_registered(cls, db: AsyncSession, user_id: int, public_key: str) -> bool:
        """
        Check if a device with this public key is already registered for the user.
        """
        result = await db.execute(
            select(cls).where(cls.user_id == user_id, cls.public_key == public_key)
        )
        device = result.scalar_one_or_none()
        print("DO I GET HERE", device)
        return device is not None

    @classmethod
    async def register_device(cls, db: AsyncSession, user_id: int, public_key: str, device_name: str | None = None):
        """
        Register a new device for the user.
        Raises ValueError if device is already registered.
        """
        #decoded_public_key = decode_public_key(public_key)

        if await cls.is_registered(db, user_id, public_key):
            raise DeviceAlreadyRegistered("Device already registered")
        
        

        device = cls(
            user_id=user_id,
            public_key=public_key,
            device_name=device_name,
            created_at=datetime.now(tz=datetime.utcnow().astimezone().tzinfo),
            last_used=None,
            revoked=False
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)  # load the generated id
        return device


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
    async def validate_challenge(cls, db: AsyncSession, challenge: str):
        """
        Validate the challenge token.
        Returns the User if the challenge exists, has not expired, and is unused.
        Raises ValueError if invalid.
        """
        result = await db.execute(
            select(cls)
            .options(selectinload(cls.user))   # preload the User relationship
            .where(cls.token == challenge)
        )
        token_obj = result.scalar_one_or_none()

        if token_obj is None:
            raise TokenNotFound("Invalid challenge token")

        now = datetime.now(tz=token_obj.expires_at.tzinfo)
        if token_obj.used:
            raise TokenUsed("Challenge token already used")
        if token_obj.expires_at < now:
            raise TokenExpired("Challenge token expired")

        # Return the associated user
        return token_obj, token_obj.user

    async def mark_used(self, db: AsyncSession):
        """
        Mark this token as used so it cannot be reused.
        """
        self.used = True
        self.used_at = datetime.now(tz=timezone.utc)  # optional: record when it was used
        db.add(self)
        await db.commit()
        await db.refresh(self)
        return self

    # @classmethod
    # async def get_valid_token(
    #     cls,
    #     db: AsyncSession,
    #     token_value: str,
    #     token_type: str
    # ):
    #     result = await db.execute(
    #         select(cls).where(
    #             cls.token == token_value,
    #             cls.token_type == token_type,
    #             cls.used == False,
    #             cls.expires_at > datetime.now(timezone.utc)
    #         )
    #     )

    #     token = result.scalar_one_or_none()

    #     if not token:
    #         raise ValueError("Invalid or expired token")

    #     return token


if __name__ == "__main__":
    pass



