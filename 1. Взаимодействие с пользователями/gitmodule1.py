from __future__ import annotations

from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_system.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- МОДЕЛЬ БД ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String)  # ФИО
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)  # Для мягкого удаления


Base.metadata.create_all(bind=engine)


# --- СХЕМЫ ДАННЫХ (Pydantic) ---
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    password_repeat: str


class UserUpdate(BaseModel):
    full_name: str | None = None


class LoginData(BaseModel):
    email: EmailStr
    password: str


# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# --- ЭНДПОИНТЫ ---
app = FastAPI()


@app.post("/register")
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if user_data.password != user_data.password_repeat:
        raise HTTPException(status_code=400, detail="Пароли не совпадают")

    db_user = db.query(User).filter(User.email == user_data.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email уже занят")

    new_user = User(
        full_name=user_data.full_name,
        email=user_data.email,
        hashed_password=pwd_context.hash(user_data.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "Регистрация успешна"}


@app.post("/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not user.is_active or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Неверные данные или аккаунт удален")

    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def get_profile(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401)
        return user
    except:
        raise HTTPException(status_code=401, detail="Невалидный токен")


@app.put("/me/update")
def update_user(token: str, data: UserUpdate, db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if data.full_name:
        user.full_name = data.full_name
    db.commit()
    return {"message": "Данные обновлены"}


@app.delete("/me/delete")
def soft_delete(token: str, db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    user.is_active = False
    db.commit()
    return {"message": "Аккаунт деактивирован (мягкое удаление)"}
