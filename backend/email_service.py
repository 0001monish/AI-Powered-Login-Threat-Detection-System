import smtplib
import random
import os

from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# ================= GENERATE OTP =================

def generate_otp():

    return str(
        random.randint(100000, 999999)
    )

# ================= SEND EMAIL =================

def send_otp_email(
    receiver_email,
    otp
):

    subject = "Your Verification Code"

    body = f"""
Your OTP verification code is:

{otp}

Do not share this code.
"""

    msg = MIMEText(body)

    msg["Subject"] = subject

    msg["From"] = EMAIL_USER

    msg["To"] = receiver_email

    server = smtplib.SMTP(
        "smtp.gmail.com",
        587
    )

    server.starttls()

    server.login(
        EMAIL_USER,
        EMAIL_PASSWORD
    )

    server.sendmail(
        EMAIL_USER,
        receiver_email,
        msg.as_string()
    )

    server.quit()