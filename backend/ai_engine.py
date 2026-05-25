from math import radians, sin, cos, sqrt, atan2
from datetime import datetime
from ml_model import predict_anomaly
from database import cursor

# ================= COUNTRY COORDS =================
COUNTRY_COORDS = {
    "India": (20.5937, 78.9629),
    "USA": (37.0902, -95.7129),
    "Russia": (61.5240, 105.3188),
    "China": (35.8617, 104.1954),
    "UK": (55.3781, -3.4360)
}

SUSPICIOUS_IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# ================= DISTANCE =================
def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)

    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1))
        * cos(radians(lat2))
        * sin(dlon / 2) ** 2
    )

    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

# ================= THREAT ENGINE =================
def detect_threat(data):

    risk_score = 0
    reasons = []

    email = data["email"]
    country = data["country"]
    device = data["device"]
    login_status = data["login_status"]
    ip = data["ip_address"]

    # ================= VPN / PROXY =================
    vpn_detected = 0
    if ip in SUSPICIOUS_IPS:
        vpn_detected = 1
        risk_score += 20
        reasons.append("VPN / Proxy Detected")

    # ================= FAILED LOGIN =================
    failed_login = 0
    if login_status.lower() == "failed":
        failed_login = 1
        risk_score += 20
        reasons.append("Failed Login Attempt")

    # ================= LOGIN HISTORY =================
    cursor.execute(
        """
        SELECT country, device, login_time
        FROM login_logs
        WHERE user_email=%s
        ORDER BY login_time DESC
        """,
        (email,)
    )

    history = cursor.fetchall()

    previous_countries = []
    previous_devices = []

    new_country = 0
    new_device = 0

    # ================= IMPOSSIBLE TRAVEL =================
    if history:

        latest_country = history[0][0]
        latest_time = history[0][2]

        if (
            latest_country in COUNTRY_COORDS
            and country in COUNTRY_COORDS
        ):

            lat1, lon1 = COUNTRY_COORDS[latest_country]
            lat2, lon2 = COUNTRY_COORDS[country]

            distance = calculate_distance(lat1, lon1, lat2, lon2)

            hours = (datetime.now() - latest_time).total_seconds() / 3600

            if hours > 0:
                speed = distance / hours

                if speed > 900:
                    risk_score += 25
                    reasons.append("Impossible Travel Detected")

    for row in history:
        previous_countries.append(str(row[0]).strip())
        previous_devices.append(str(row[1]).strip())

    # ================= NEW COUNTRY =================
    if previous_countries and country not in previous_countries:
        new_country = 1
        risk_score += 25
        reasons.append("New Login Country")

    # ================= NEW DEVICE =================
    if previous_devices and device not in previous_devices:
        new_device = 1
        risk_score += 25
        reasons.append("Unknown Device")

    # ================= BRUTE FORCE =================
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM login_logs
        WHERE user_email=%s
        AND login_status='failed'
        """,
        (email,)
    )

    failed_count = cursor.fetchone()[0]

    if failed_count >= 5:
        risk_score += 20
        reasons.append("Possible Brute Force Attack")

    # ================= ML MODEL =================
    ml_result = predict_anomaly(
        new_device,
        new_country,
        vpn_detected,
        failed_login
    )

    if ml_result == -1:
        risk_score += 20
        reasons.append("ML Anomaly Detection")

    # ================= NORMALIZATION (IMPORTANT FIX) =================
    risk_score = min(risk_score, 100)

    # ================= RISK LEVEL =================
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "is_threat": risk_score >= 40,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "ml_prediction": "Anomaly" if ml_result == -1 else "Normal"
    }