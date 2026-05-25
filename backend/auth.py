from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import re

SECRET_KEY = "SUPER_SECRET_KEY"

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# ================= HASH PASSWORD =================

def hash_password(password):

    password = password[:72]

    return pwd_context.hash(password)

def validate_password(password):

    # Minimum 8 chars
    if len(password) < 8:

        return False, "Password must be at least 8 characters"

    # Uppercase
    if not re.search(r"[A-Z]", password):

        return False, "Password must contain an uppercase letter"

    # Lowercase
    if not re.search(r"[a-z]", password):

        return False, "Password must contain a lowercase letter"

    # Number
    if not re.search(r"\d", password):

        return False, "Password must contain a number"

    # Special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):

        return False, "Password must contain a special character"

    return True, "Strong password"

# ================= VERIFY PASSWORD =================

def verify_password(
    plain_password,
    hashed_password
):

    plain_password = plain_password[:72]

    return pwd_context.verify(
        plain_password,
        hashed_password
    )

# ================= CREATE JWT =================

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        "exp": expire
    })

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )