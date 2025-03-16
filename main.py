import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import psycopg2
import random
from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

app = FastAPI()

# Параметры подключения к Supabase через переменные окружения
PGSQL_CONFIG = {
    "host": os.getenv("SUPABASE_HOST", "db.usrafshcraymcxtqkuyr.supabase.co"),
    "port": 5432,
    "database": "postgres",
    "user": "postgres",
    "password": os.getenv("SUPABASE_PASSWORD", "rUBEC200312"),
    "sslmode": "require"
}

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db_connection():
    return psycopg2.connect(**PGSQL_CONFIG)

@app.get("/")
def read_root():
    return {"message": "Welcome to the API!"}

@app.get("/test-db")
async def test_db():
    conn = None
    try:
        conn = get_db_connection()
        return {"message": "Database connection successful"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(err)}")
    finally:
        if conn:
            conn.close()

@app.post("/signup")
async def signup(nickname: str, email: str, password: str):
    hashed_password = pwd_context.hash(password)
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (nickname, email, password) VALUES (%s, %s, %s) RETURNING id",
                       (nickname, email, hashed_password))
        user_id = cursor.fetchone()[0]
        conn.commit()
        return {"message": "User created successfully", "user_id": user_id}
    except psycopg2.Error as err:
        if "duplicate key value violates unique constraint" in str(err).lower():
            raise HTTPException(status_code=400, detail="Email already exists")
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/login")
async def login(email: str, password: str):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user and pwd_context.verify(password, user[3]):  # user[3] - это поле password
            return {"message": "Login successful", "user_id": user[0]}
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/generate_reset_code")
async def generate_reset_code(email: str):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверка, существует ли пользователь
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Email not found")

        # Генерация кода и времени истечения
        code = str(random.randint(100000, 999999))
        expires_at = datetime.now() + timedelta(minutes=10)

        # Сохранение кода в базе
        cursor.execute("INSERT INTO password_resets (email, reset_code, expires_at) VALUES (%s, %s, %s) "
                      "ON CONFLICT (email) DO UPDATE SET reset_code=%s, expires_at=%s",
                      (email, code, expires_at, code, expires_at))
        conn.commit()

        return {"message": "Reset code generated", "code": code}  # Для теста, в продакшене убрать возврат кода
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/verify_reset_code")
async def verify_reset_code(email: str, code: str):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        now = datetime.now()
        cursor.execute("SELECT * FROM password_resets WHERE email=%s AND reset_code=%s AND expires_at > %s",
                       (email, code, now))
        result = cursor.fetchone()

        if result:
            cursor.execute("DELETE FROM password_resets WHERE email=%s", (email,))
            conn.commit()
            return {"message": "Code verified successfully"}
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/reset_password")
async def reset_password(email: str, new_password: str):
    hashed_password = pwd_context.hash(new_password)
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Email not found")
        conn.commit()
        return {"message": "Password reset successfully"}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()

@app.post("/add_course")
async def add_course(name: str):
    conn = None
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
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM courses")
        courses = [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]
        return {"courses": courses}
    except psycopg2.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if conn:
            cursor.close()
            conn.close()