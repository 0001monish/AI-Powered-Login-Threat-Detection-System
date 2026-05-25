# AI-Powered Login Threat Detection & Risk-Based Authentication System

## Overview

An AI-driven cybersecurity project that enhances traditional authentication systems by detecting suspicious login behavior, calculating risk scores, and triggering Multi-Factor Authentication (MFA) when necessary.

The system combines rule-based threat detection with machine learning anomaly detection to improve account security and reduce unauthorized access.

---

## Features

### Authentication & Security

- User Registration
- Password Strength Validation
- Password Hashing (bcrypt)
- JWT Authentication
- Email OTP Verification
- OTP Expiry & Resend Limits
- Account Lock after Multiple Failed Attempts
- IP-Based Rate Limiting

### AI Threat Detection

- VPN / Proxy Detection
- Failed Login Detection
- New Device Detection
- New Country Detection
- Impossible Travel Detection
- Brute Force Detection

### Machine Learning

- Isolation Forest Anomaly Detection
- Login Behavior Analysis
- Risk Score Generation
- Threat Classification

### Risk-Based Authentication

- Dynamic Risk Scoring (0–100)
- LOW / MEDIUM / HIGH Risk Levels
- Adaptive MFA Triggering
- Email OTP Verification for High-Risk Logins

### Dashboard

- Total Users
- Total Logins
- Threat Analytics
- Recent Login Activity
- Risk Monitoring

---

## Technology Stack

### Backend

- Python
- FastAPI

### Database

- PostgreSQL
- Neon Database

### Security

- JWT (python-jose)
- bcrypt (Passlib)
- SMTP Email OTP

### AI / Machine Learning

- Scikit-Learn
- Isolation Forest
- Pandas
- NumPy

### Dashboard

- Streamlit

### Tools

- Postman
- Git
- GitHub
- VS Code

---

## Project Architecture

User
→ FastAPI Backend
→ Authentication Module
→ AI Threat Detection Engine
→ Isolation Forest ML Model
→ Risk Scoring Engine
→ PostgreSQL Database
→ MFA System
→ Streamlit Dashboard

---

## Database Tables

### users

- email
- password
- device
- country
- otp_code
- is_verified
- failed_attempts
- locked_until

### login_logs

- user_email
- ip_address
- device
- country
- login_status
- login_time

### threats

- user_email
- threat_type
- risk_level
- risk_score

### ip_rate_limits

- ip_address
- request_count
- window_start

---

## Machine Learning Model

Algorithm:

- Isolation Forest

Features:

- new_device
- new_country
- vpn_detected
- failed_login

Output:

- Normal
- Anomaly

---

## Installation

```bash
git clone <repository-url>
cd project-folder

pip install -r requirements.txt
```
