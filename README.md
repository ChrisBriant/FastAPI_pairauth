# PairAuth - Passwordless QR Authentication

PairAuth is a passwordless authentication system that allows users to log in to a web app by scanning a QR code with a mobile authenticator app. The system uses public/private key pairs for secure device authentication and supports traditional username/password signup as well.

---

## Features

- Traditional username/password signup
- Passwordless login via QR codes
- Device registration and management
- Short-lived registration challenges for secure device pairing
- Backend built with Python and SQLAlchemy
- Frontend built with React for web and Flutter for mobile authenticator app

---

## Database Models

### Users Table

Stores registered users:

- `id`: Primary key  
- `user_name`: Unique username  
- `password_hash`: Securely hashed password  
- `created_at`: Timestamp  

### Devices Table

Stores registered devices after QR scan:

- `id`: Primary key  
- `user_id`: Foreign key to `users`  
- `device_name`: Optional human-readable name  
- `public_key`: Device public key for authentication  
- `created_at`: Timestamp  
- `last_used`: Timestamp of last login  
- `revoked`: Boolean for revoking access  

### Tokens Table

Stores short-lived tokens for QR login:

- `id`: Primary key  
- `user_id`: Foreign key to `users`  
- `device_id`: Foreign key to `devices` (after device registers)  
- `token`: Short-lived registration/login token  
- `expires_at`: Expiration timestamp  
- `used`: Boolean to prevent replay attacks  
- `created_at`: Timestamp  

---

## Backend Flow

### User Sign-Up

1. **Create user** — hash password and insert into `users` table  
2. **Validate input** — ensure username/email is unique  
3. **Generate registration challenge** — a secure random token for QR  
4. **Send challenge to frontend** — React encodes it as a QR code  
5. **Device registration** — Flutter app scans QR, generates key pair, sends public key + challenge to backend  
6. **Create device record** — backend validates challenge, stores public key in `devices` table  

### QR Login

1. React app requests login QR — backend generates short-lived login token  
2. QR contains deep link with token  
3. Flutter app scans QR, signs challenge with device private key  
4. Backend verifies signature using device public key  
5. Backend issues JWT/session for React app  

---

## Setup

### Backend

1. Install Python dependencies: pip  instal -r requirements.txt

uvicorn main:app --reload


## Questions

1. How do you handle device registration if a user exists, but they don't register the device in time?


### Auth Flow

1. React user registers account
2. Backend - Accept user name password and store in DB
3. Backend generates challenge code
4. React receives challenge code and displays QR code + challenge
5. Mobile Device - User scans QR code or enters manually
6. Mobile Device - Generate public and private key pair, store securely
7. Send public key + challenge code to backend
8. Backend - Looks up challenge code, if successful registered device with user