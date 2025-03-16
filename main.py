import os
from fastapi import FastAPI, HTTPException, Body
import psycopg2
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import requests
from fastapi.responses import RedirectResponse
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Конфигурация подключения к Supabase через Session Pooler
PGSQL_CONFIG = {
    "host": "aws-0-eu-central-1.pooler.supabase.com",
    "port": 6543,
    "database": "postgres",
    "user": "postgres.usrafshcraymcxtqkuyr",
    "password": os.getenv("SUPABASE_PASSWORD", "rUBEC200312"),
    "sslmode": "require"
}

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Настройка email
EMAIL_USER = os.getenv("EMAIL_USER", "DrMehrunes@yandex.ru")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "ieuhbnegqnbosioe")
EMAIL_HOST = "smtp.yandex.ru"
EMAIL_PORT = 465

# Путь к client_secret.json на сервере
CLIENT_SECRET_FILE = "client_secret.json"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
auth_tokens = {}

def get_db_connection():
    try:
        conn = psycopg2.connect(**PGSQL_CONFIG)
        return conn
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(err)}")

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up the application...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                nickname VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                email VARCHAR(255) NOT NULL,
                reset_code VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                PRIMARY KEY (email)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS courses (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL
            )
        """)
        conn.commit()
        logger.info("Database tables created successfully")
    except psycopg2.Error as err:
        logger.error(f"Error initializing database: {err}")
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/signup")
async def signup(nickname: str = Body(...), email: str = Body(...), password: str = Body(...)):
    logger.info(f"Signup attempt for email: {email}")
    hashed_password = pwd_context.hash(password)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s AND nickname = %s", (email, nickname))
        user_with_nickname_and_email = cursor.fetchone()
        if user_with_nickname_and_email:
            raise HTTPException(status_code=400, detail="A user with this nickname and email already exists")
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_with_email = cursor.fetchone()
        if user_with_email:
            raise HTTPException(status_code=400, detail="A user with this email already exists")
        
        cursor.execute(
            "INSERT INTO users (nickname, email, password) VALUES (%s, %s, %s) RETURNING id",
            (nickname, email, hashed_password)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        logger.info(f"User created successfully with ID: {user_id}")
        return {"message": "User created successfully", "user_id": user_id}
    except psycopg2.Error as err:
        logger.error(f"Database error during signup: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/login")
async def login(email: str = Body(...), password: str = Body(...)):
    logger.info(f"Login attempt for email: {email}")
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not pwd_context.verify(password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        logger.info(f"Login successful for user ID: {user['id']}")
        return {"message": "Login successful", "user_id": user["id"]}
    except psycopg2.Error as err:
        logger.error(f"Database error during login: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/generate_reset_code")
async def generate_reset_code(email: str = Body(..., embed=True)):
    logger.info(f"Generating reset code for email: {email}")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required.")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Email not found")
        
        code = str(random.randint(100000, 999999))
        expires_at = datetime.now() + timedelta(minutes=10)
        
        cursor.execute("DELETE FROM password_resets WHERE email = %s", (email,))
        cursor.execute(
            "INSERT INTO password_resets (email, reset_code, expires_at) VALUES (%s, %s, %s)",
            (email, code, expires_at)
        )
        conn.commit()
        
        sender_email = EMAIL_USER
        sender_name = "DrMehrunes"
        msg = MIMEMultipart()
        msg["From"] = formataddr((sender_name, sender_email))
        msg["To"] = email
        msg["Subject"] = "Password Recovery"
        msg.attach(MIMEText(f"Your recovery code: {code}\nValid for 10 minutes.", "plain"))
        
        with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as server:
            server.login(sender_email, EMAIL_PASSWORD)
            server.sendmail(sender_email, email, msg.as_string())
        
        logger.info(f"Reset code sent to email: {email}")
        return {"message": "Reset code sent to your email"}
    except psycopg2.Error as err:
        logger.error(f"Database error during reset code generation: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/verify_reset_code")
async def verify_reset_code(email: str = Body(...), code: str = Body(...)):
    logger.info(f"Verifying reset code for email: {email}")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM password_resets WHERE email = %s AND reset_code = %s AND expires_at > %s",
            (email, code, datetime.now())
        )
        reset_record = cursor.fetchone()
        if not reset_record:
            raise HTTPException(status_code=400, detail="Invalid or expired code")
        
        cursor.execute("DELETE FROM password_resets WHERE email = %s", (email,))
        conn.commit()
        logger.info(f"Reset code verified for email: {email}")
        return {"message": "Code verified"}
    except psycopg2.Error as err:
        logger.error(f"Database error during code verification: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/reset_password")
async def reset_password(email: str = Body(...), new_password: str = Body(...)):
    logger.info(f"Resetting password for email: {email}")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        hashed_password = pwd_context.hash(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        logger.info(f"Password reset successfully for email: {email}")
        return {"message": "Password reset successfully"}
    except psycopg2.Error as err:
        logger.error(f"Database error during password reset: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/add_course")
async def add_course(name: str = Body(...)):
    logger.info(f"Adding course with name: {name}")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO courses (name) VALUES (%s) RETURNING id", (name,))
        course_id = cursor.fetchone()[0]
        conn.commit()
        logger.info(f"Course added successfully with ID: {course_id}")
        return {"message": "Course added successfully", "course_id": course_id}
    except psycopg2.Error as err:
        logger.error(f"Database error during course addition: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.get("/courses")
async def get_courses():
    logger.info("Fetching all courses")
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, name FROM courses")
        courses = cursor.fetchall()
        logger.info(f"Fetched {len(courses)} courses")
        return {"courses": courses}
    except psycopg2.Error as err:
        logger.error(f"Database error during fetching courses: {err}")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

auth_tokens = {}

@app.get("/google-auth")
async def google_auth_redirect():
    logger.info("Initiating Google authentication")
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRET_FILE,
            scopes=SCOPES,
            redirect_uri="https://server-zitz.onrender.com/google-auth/callback"
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true"
        )
        auth_tokens[state] = {"status": "pending"}
        logger.info(f"Redirecting to Google auth URL with state: {state}")
        return RedirectResponse(authorization_url)
    except FileNotFoundError as e:
        logger.error("Client secrets file not found")
        raise HTTPException(status_code=500, detail="Client secrets file not found.")
    except ValueError as e:
        logger.error(f"Invalid client secrets file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Invalid client secrets file: {str(e)}")
    except Exception as e:
        logger.error(f"Google auth failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Google auth failed: {str(e)}")
    
@app.get("/google-auth/callback")
async def google_auth_callback(code: str, state: str):
    logger.info(f"Handling Google auth callback with state: {state}")
    if state not in auth_tokens:
        logger.error(f"State {state} not found in auth_tokens")
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRET_FILE,
            scopes=SCOPES,
            redirect_uri="https://server-zitz.onrender.com/google-auth/callback"
        )
        logger.info("Fetching token...")
        flow.fetch_token(code=code)
        creds = flow.credentials
        logger.info("Token fetched successfully")

        user_info = await get_user_info(creds.token)
        if not user_info:
            logger.error("Failed to retrieve user info")
            auth_tokens[state] = {"status": "error", "detail": "Failed to retrieve user info"}
            raise HTTPException(status_code=400, detail="Failed to retrieve user info")

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (user_info["email"],))
        user = cursor.fetchone()

        if not user:
            nickname = user_info.get("name", user_info["email"].split("@")[0])
            password = pwd_context.hash(str(random.randint(100000, 999999)))
            cursor.execute(
                "INSERT INTO users (nickname, email, password) VALUES (%s, %s, %s) RETURNING id",
                (nickname, user_info["email"], password)
            )
            user_id = cursor.fetchone()["id"]
            logger.info(f"Created new user with ID: {user_id}")
        else:
            user_id = user["id"]
            logger.info(f"Found existing user with ID: {user_id}")

        conn.commit()
        cursor.close()
        conn.close()

        auth_tokens[state] = {
            "status": "success",
            "user_id": user_id,
            "token": creds.token,
            "refresh_token": creds.refresh_token
        }
        logger.info("Google authentication successful")
        return {"message": "Google authentication successful. You can close this window."}
    except Exception as e:
        auth_tokens[state] = {"status": "error", "detail": str(e)}
        logger.error(f"Google auth failed in callback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Google auth failed: {str(e)}")

@app.get("/google-auth/status/{state}")
async def check_auth_status(state: str):
    logger.info(f"Checking auth status for state: {state}")
    if state not in auth_tokens:
        logger.error("State not found")
        raise HTTPException(status_code=404, detail="State not found")
    return auth_tokens[state]

async def get_user_info(token: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

@app.get("/test-db")
async def test_db():
    logger.info("Testing database connection")
    conn = None
    try:
        conn = get_db_connection()
        logger.info("Database connection successful")
        return {"message": "Database connection successful"}
    except psycopg2.Error as err:
        logger.error(f"Database connection failed: {str(err)}")
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(err)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    finally:
        if conn:
            conn.close()