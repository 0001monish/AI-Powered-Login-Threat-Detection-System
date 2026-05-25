from pydantic import BaseModel, EmailStr

# ================= REGISTER =================

class RegisterRequest(BaseModel):

    email: EmailStr
    password: str
    device: str
    country: str

# ================= LOGIN =================

class LoginAuthRequest(BaseModel):

    email: EmailStr
    password: str
    device: str
    country: str

# ================= LOGIN EVENT =================

class LoginRequest(BaseModel):

    email: str
    ip_address: str
    device: str
    country: str
    login_status: str

# ================= OTP VERIFY =================

class VerifyOTPRequest(BaseModel):

    email: EmailStr
    otp_code: str