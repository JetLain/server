import os
from fastapi import FastAPI, HTTPException, Body  # Добавляем импорт Body
import psycopg2
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

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

def get_db_connection():
    try:
        conn = psycopg2.connect(**PGSQL_CONFIG)
        return conn
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(err)}")

@app.on_event("startup")
async def startup_event():
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
    except psycopg2.Error as err:
        print(f"Error initializing database: {err}")
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/signup")
async def signup(nickname: str = Body(...), email: str = Body(...), password: str = Body(...)):
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
        return {"message": "User created successfully", "user_id": user_id}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/login")
async def login(email: str = Body(...), password: str = Body(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not pwd_context.verify(password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        return {"message": "Login successful", "user_id": user["id"]}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/generate_reset_code")
async def generate_reset_code(email: str = Body(..., embed=True)):
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
        
        return {"message": "Reset code sent to your email"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/verify_reset_code")
async def verify_reset_code(email: str = Body(...), code: str = Body(...)):
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
        return {"message": "Code verified"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/reset_password")
async def reset_password(email: str = Body(...), new_password: str = Body(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        hashed_password = pwd_context.hash(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        return {"message": "Password reset successfully"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/add_course")
async def add_course(name: str = Body(...)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO courses (name) VALUES (%s) RETURNING id", (name,))
        course_id = cursor.fetchone()[0]
        conn.commit()
        return {"message": "Course added successfully", "course_id": course_id}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.get("/courses")
async def get_courses():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, name FROM courses")
        courses = cursor.fetchall()
        return {"courses": courses}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.get("/test-db")
async def test_db():
    conn = None
    try:
        conn = get_db_connection()
        return {"message": "Database connection successful"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(err)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    finally:
        if conn:
            conn.close()