from fastapi import APIRouter, HTTPException, Request, Depends, Response, Query, status
from typing import List
from data.db import SessionLocal
from pathlib import Path
from data.models import User, Token, Device
from data.schemas import (
    UserInputSchema,
    DeviceRegistrationInput,
)
import json
import os
import base64
from services.auth_exceptions import TokenExpired, TokenNotFound, TokenUsed, DeviceAlreadyRegistered
from services.auth import verify_signature

router = APIRouter()

# Go to project root (adjust parents[n] if needed)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@router.post("/signup", response_model =str, status_code=status.HTTP_201_CREATED)
async def signup_user(user_input : UserInputSchema):
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

        #Insert challenge code into database
        try:
            challenge_code = await Token.create_challenge(session,user.id,token_type="registration",expires_minutes=180)
            if not challenge_code:
                raise HTTPException(status_code=400,detail="Challenge code not created")
            return challenge_code.token
        except Exception as e:
            print("VALUE ERROR", e)
            raise HTTPException(status_code=400,detail="Unable to set the challenge token")            


@router.post("/registerdevice", response_model =str, status_code=status.HTTP_201_CREATED)
async def register_device(reg_input : DeviceRegistrationInput):
    #1. Lookup challenge code 
    async with SessionLocal() as session:
        try:
            token, user = await Token.validate_challenge(session,reg_input.challenge_code)
            print("USER WITH CHALLENGE CODE",user)
        except TokenUsed as tu:
            print("TOKEN USED", tu)
            raise HTTPException(status_code=401,detail="Token is already used")
        except TokenExpired as te:
            print("TOKEN EXPIRED", te)
            raise HTTPException(status_code=401,detail="The token has expired")
        except TokenNotFound as tnf:
            print("TOKEN NOT FOUND", tnf)
            raise HTTPException(status_code=401,detail="Invalid token sent")
  
        #2. Verify signature
        if user:
            signature_verified = verify_signature(reg_input.public_key,reg_input.signature,reg_input.challenge_code)
            if not signature_verified:
                raise HTTPException(status_code=401,detail="Signature is not valid")

            #3. Check no device is already registered and Register device - Add device record to DB
            try:
                device = await Device.register_device(session,user.id,reg_input.public_key,reg_input.device_name)
                if not device:
                    raise HTTPException(status_code=422,detail="Device registration failed")
                #4. Mark token as used
                try:
                    await token.mark_used(session)
                except Exception as e:
                    raise HTTPException(status_code=422,detail="Unable to mark token as used")
            except DeviceAlreadyRegistered as dar:
                print("DEVICE IS ALREADY REGISTERED", dar)
                raise HTTPException(status_code=401,detail="Device is already registered")
            except Exception as e:
                print("An unknown error occurred")
                raise HTTPException(status_code=400,detail="An unknown error occurred")
            

    return "Device Registered" 



    