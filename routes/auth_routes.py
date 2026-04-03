from fastapi import APIRouter, HTTPException, Request, Depends, Response, Query, status
from fastapi.responses import RedirectResponse
from typing import List
from data.db import SessionLocal
from pathlib import Path
from data.models import User, Token, Device
from data.schemas import (
    UserInputSchema,
    DeviceRegistrationInput,
    DeviceAuthenticationInputSchema,
)
import json
import os
import base64
from services.auth_exceptions import TokenExpired, TokenNotFound, TokenUsed, DeviceAlreadyRegistered
from services.auth import verify_signature
from services.token import ACCESS_TOKEN_LIFETIME, REFRESH_TOKEN_LIFETIME,obtain_jwt_pair
from services.utils import check_active_device_exists


router = APIRouter()

# Go to project root (adjust parents[n] if needed)
PROJECT_ROOT = Path(__file__).resolve().parents[1]

CHALLENGE_TOKEN_LIFETIME = 200


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


@router.post("/registerdevice", response_model =int, status_code=status.HTTP_201_CREATED)
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
  
        #FOR TESTING PURPOSES
        #user = await User.get_by_id(session,8)

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
            
            #DON@T DO BELOW HERE JUST RETURN SUCCESS
            #Issue a jwt and set the cookies
            #Issue a JWT
            
            # jwt_token_pair = obtain_jwt_pair(str(user.id),user.user_name, user.terms_accepted) 
            # response = RedirectResponse(
            #     url=os.environ.get("CLIENT_REDIRECT"),
            #     status_code=302
            # )
            # # Access token cookie
            # response.set_cookie(
            #     key="access_token",
            #     value=jwt_token_pair["access"],
            #     httponly=True,
            #     secure=True,          # HTTPS only
            #     samesite="none",
            #     max_age=ACCESS_TOKEN_LIFETIME,
            # )

            # # Refresh token cookie
            # response.set_cookie(
            #     key="refresh_token",
            #     value=jwt_token_pair["refresh"],
            #     httponly=True,
            #     secure=True,
            #     samesite="none",
            #     max_age=REFRESH_TOKEN_LIFETIME, 
            # )
            return device.id



@router.post("/signin", response_model =str, status_code=status.HTTP_200_OK)
async def signin_user(response: Response, user_input : UserInputSchema):
    """
        Endpoint to handle user sign in.
        Takes the user name and password, checks device is registered, validates user password, sets challenge cookie
    """
    async with SessionLocal() as session:
        #1.Check user is registered
        user = await User.get_by_user_name(session,user_input.user_name)
        if not user:
            raise HTTPException(status_code=404,detail="User not found")
        #Check the devices is more than one which means they have registered
        print("USER FOUND", list(user.devices))
        device_list = list(user.devices)
        if not (len(device_list) > 0 and check_active_device_exists(device_list)):
            raise HTTPException(status_code=404,detail="Could not find active device") 
        #2. Verify the user password
        print(type(user))                   # should be <class 'User'>
        print(user.password_hash)           # should be the actual hash string
        password_valid = user.verify_password(user_input.password)
        if not password_valid:
            raise HTTPException(status_code=401,detail="Password authentication failed")
        print("PASSWORD IS VALID", password_valid)
        #3. Create a challenge for device authentication
        challenge = await Token.create_challenge(session,user.id,"signin",200)
        #Create challenge cookie and redirect to challenge page on browser app
        # response = RedirectResponse(
        #     url=f"{os.environ.get("CLIENT_REDIRECT")}/challenge?type=signIn",
        #     status_code=302
        # )
        # Access token cookie
        response.set_cookie(
            key="challenge_token",
            value=challenge.token,
            httponly=True,
            secure=True,          # HTTPS only
            samesite="none",
            max_age=CHALLENGE_TOKEN_LIFETIME,
        )
        

        return challenge.token
    
@router.post("/deviceauth", response_model =str, status_code=status.HTTP_200_OK)
async def authenticate_device(device_input : DeviceAuthenticationInputSchema):
    """
        Endpoint to authenticate a device
    """
    async with SessionLocal() as session:
        #1.Get the device
        device = await Device.get_by_id(session,device_input.device_id)
        if not device:
            raise HTTPException(status_code=404,detail="Device not registered")
        print("DEVICE FOUND", device)
        #2.Verify the signature against the device public key
        signature_verified = verify_signature(device.public_key,device_input.signature,device_input.challenge_code)
        if not signature_verified:
            raise HTTPException(status_code=404,detail="Signature not valid")
        print("DEVICE SIGNATURE VERIFIED", signature_verified)
        #3. Get the token and user
        try:
            token, user = await Token.validate_challenge(session,device_input.challenge_code)
            print("TOKEN",token)
            await token.mark_verified(session)
        except TokenUsed as tu:
            print("TOKEN USED", tu)
            raise HTTPException(status_code=401,detail="Token is already used")
        except TokenExpired as te:
            print("TOKEN EXPIRED", te)
            raise HTTPException(status_code=401,detail="The token has expired")
        except TokenNotFound as tnf:
            print("TOKEN NOT FOUND", tnf)
            raise HTTPException(status_code=401,detail="Invalid token sent")
  
    return "successful"

@router.get("/complete-signin", response_model =str)
async def complete_signin(request : Request):
    """
        Completes the sign in process by verifying the device has been authenticated and issues a JWT pair then redirects.
    """
    challenge_cookie = request.cookies.get("challenge_token")
    print("CHALLENGE COOKIE", challenge_cookie)
    async with SessionLocal() as session:
        try:
            token, user = await Token.validate_challenge(session,challenge_cookie)
            if not token.verified:
                raise HTTPException(status_code=401,detail="Invalid token sent - token is not verified")
            #Issue JWT and set session and refresh tokens
            jwt_token_pair = obtain_jwt_pair(user.id, user.user_name, user.terms_accepted)
            response = RedirectResponse(
                url= f"{os.environ.get('CLIENT_REDIRECT')}/home",
                status_code=302
            )
            # Access token cookie
            response.set_cookie(
                key="access_token",
                value=jwt_token_pair["access"],
                httponly=True,
                secure=True,          # HTTPS only
                samesite="none",
                max_age=ACCESS_TOKEN_LIFETIME,
            )

            # Refresh token cookie
            response.set_cookie(
                key="refresh_token",
                value=jwt_token_pair["refresh"],
                httponly=True,
                secure=True,
                samesite="none",
                max_age=REFRESH_TOKEN_LIFETIME, 
            )
            # Mark the token as used 
            try:
                await token.mark_used(session)
            except Exception as e:
                raise HTTPException(status_code=422,detail="Unable to mark token as used")
        except TokenUsed as tu:
            print("TOKEN USED", tu)
            raise HTTPException(status_code=401,detail="Token is already used")
        except TokenExpired as te:
            print("TOKEN EXPIRED", te)
            raise HTTPException(status_code=401,detail="The token has expired")
        except TokenNotFound as tnf:
            print("TOKEN NOT FOUND", tnf)
            raise HTTPException(status_code=401,detail="Invalid token sent")

    return response

