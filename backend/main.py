from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from database import cursor, conn
from datetime import datetime, timedelta
from ai_engine import detect_threat
from zoneinfo import ZoneInfo
from rate_limiter import check_rate_limit

from email_service import generate_otp, send_otp_email

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    validate_password
)

from models import (
    RegisterRequest,
    LoginAuthRequest,
    LoginRequest,
    VerifyOTPRequest
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= HOME =================
@app.get("/")
def home():
    return {"message": "AI Login Threat System Running 🚀"}

# ================= REGISTER =================
@app.post("/register")
def register(data: RegisterRequest):

    email = data.email.strip().lower()

    cursor.execute(
        "SELECT * FROM users WHERE email=%s",
        (email,)
    )

    if cursor.fetchone():
        return {"error": "User already exists"}

    is_valid, message = validate_password(data.password)

    if not is_valid:
        return {"error": message}

    hashed_password = hash_password(data.password)
    otp = generate_otp()

    cursor.execute(
        """
        INSERT INTO users
        (email, password, device, country, otp_code, otp_created_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
        """,
        (
            email,
            hashed_password,
            data.device,
            data.country,
            otp
        )
    )

    conn.commit()

    send_otp_email(email, otp)

    return {"message": "OTP sent to email"}

# ================= VERIFY OTP =================
@app.post("/verify-otp")
def verify_otp(data: VerifyOTPRequest):

    email = data.email.strip().lower()

    cursor.execute(
        """
        SELECT otp_code, otp_created_at
        FROM users
        WHERE email=%s
        """,
        (email,)
    )

    result = cursor.fetchone()

    if not result:
        return {"error": "User not found"}

    stored_otp, otp_created_at = result

    otp_created_at = otp_created_at.replace(tzinfo=None)
    expiry_time = otp_created_at + timedelta(minutes=5)

    if stored_otp != data.otp_code:
        return {"error": "Invalid OTP"}

    if datetime.utcnow() > expiry_time:
        return {"error": "OTP expired"}

    cursor.execute(
        """
        UPDATE users
        SET is_verified=TRUE, otp_resend_count=0
        WHERE email=%s
        """,
        (email,)
    )

    conn.commit()

    return {"message": "Email verified successfully"}

# ================= LOGIN =================
@app.post("/login")
def login(data: LoginAuthRequest, request: Request):

    email = data.email.strip().lower()

    ip = request.client.host

    if not check_rate_limit(ip):
        return {"error": "Too many login requests"}

    cursor.execute(
        """
        SELECT password, is_verified, failed_attempts, locked_until
        FROM users
        WHERE email=%s
        """,
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        return {"error": "Invalid email"}

    hashed_password, is_verified, failed_attempts, locked_until = user

    if not is_verified:
        return {"error": "Email not verified"}

    # lock check
    if locked_until:
        now = datetime.now(ZoneInfo("Asia/Kolkata"))

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=ZoneInfo("Asia/Kolkata"))

        if now < locked_until:
            return {
                "error": "Account locked",
                "locked_until": str(locked_until)
            }

    if not verify_password(data.password, hashed_password):

        failed_attempts += 1

        if failed_attempts >= 5:
            lock_until = datetime.now(ZoneInfo("Asia/Kolkata")) + timedelta(minutes=15)

            cursor.execute(
                """
                UPDATE users
                SET failed_attempts=%s, locked_until=%s
                WHERE email=%s
                """,
                (failed_attempts, lock_until, email)
            )

            conn.commit()

            return {
                "error": "Account locked for 15 minutes",
                "locked_until": str(lock_until)
            }

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts=%s
            WHERE email=%s
            """,
            (failed_attempts, email)
        )

        conn.commit()

        return {"error": f"Invalid password {failed_attempts}/5"}

    cursor.execute(
        """
        UPDATE users
        SET failed_attempts=0, locked_until=NULL
        WHERE email=%s
        """,
        (email,)
    )

    conn.commit()

    token = create_access_token({"sub": email})

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ================= LOGIN EVENT =================
@app.post("/login-event")
def login_event(data: LoginRequest):

    result = detect_threat(data.dict())

    cursor.execute(
        """
        INSERT INTO login_logs
        (user_email, ip_address, device, country, login_status)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            data.email.strip().lower(),
            data.ip_address,
            data.device,
            data.country,
            data.login_status
        )
    )

    conn.commit()

    if result["is_threat"]:
        for reason in result["reasons"]:
            cursor.execute(
                """
                INSERT INTO threats
                (user_email, threat_type, risk_level, risk_score)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    data.email,
                    reason,
                    result["risk_level"],
                    result["risk_score"]
                )
            )

        conn.commit()

    if result["risk_score"] >= 70:

        otp = generate_otp()

        cursor.execute(
            """
            UPDATE users
            SET otp_code=%s, otp_created_at=NOW()
            WHERE email=%s
            """,
            (otp, data.email.strip().lower())
        )

        conn.commit()

        send_otp_email(data.email, otp)

        return {
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "message": "High risk login detected. OTP sent.",
            "mfa_required": True
        }

    return result

# ================= RESEND OTP =================
@app.post("/resend-otp")
def resend_otp(email: str):

    email = email.strip().lower()

    cursor.execute(
        "SELECT otp_resend_count FROM users WHERE email=%s",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        return {"error": "User not found"}

    count = user[0]

    if count >= 3:
        return {"error": "OTP limit reached"}

    otp = generate_otp()

    cursor.execute(
        """
        UPDATE users
        SET otp_code=%s,
            otp_created_at=NOW(),
            otp_resend_count=otp_resend_count + 1
        WHERE email=%s
        """,
        (otp, email)
    )

    conn.commit()

    send_otp_email(email, otp)

    return {
        "message": "OTP sent",
        "remaining": 3 - (count + 1)
    }