from fastapi import APIRouter, HTTPException, Request, Depends, Response, Query, status
from typing import List
from data.db import SessionLocal
from pathlib import Path
from data.models import User, Token
from data.schemas import (
    UserInputSchema
)
import json
import os
import base64

router = APIRouter()

# Go to project root (adjust parents[n] if needed)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@router.post("/signup", response_model =str, status_code=status.HTTP_201_CREATED)
async def get_providers(user_input : UserInputSchema):
    """
        Sign up a User
        1. Create user — hash password and insert into users table.
        2. Validate input — ensure username/email is unique and meets requirements.
        3. Generate device registration challenge — prepare QR / key pair setup.
    """

    async with SessionLocal() as session:
        try:
            user = await User.create_user(session,user_input.user_name,user_input.password)
        except ValueError as ve:
            print("VALUE ERROR", ve)
            raise HTTPException(status_code=409,detail="User already exists")
        print("CREATED USER", user)
        if not user:
            raise HTTPException(status_code=400,detail="User not created")
        challenge_code = user.generate_registration_challenge()
        print("CHALLENGE CODE", challenge_code)
        if not challenge_code:
            raise HTTPException(status_code=400,detail="Challenge code not created")
        #Insert challenge code into database
        try:
            await Token.create_challenge(session,user.id)
        except Exception as e:
            print("VALUE ERROR", e)
            raise HTTPException(status_code=400,detail="Unable to set the challenge token")            

    return challenge_code