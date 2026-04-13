from fastapi import FastAPI, HTTPException, Depends, Request
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Table
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base

# --- 1. НАСТРОЙКИ БАЗЫ ДАННЫХ ---
Base = declarative_base()
engine = create_engine("sqlite:///./auth_system.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

# Таблицы связей для ролей и прав
user_roles = Table('user_roles', Base.metadata,
    Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('role_id', ForeignKey('roles.id'), primary_key=True)
)

role_permissions = Table('role_permissions', Base.metadata,
    Column('role_id', ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', ForeignKey('permissions.id'), primary_key=True)
)

# --- 2. МОДЕЛИ ДАННЫХ ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    is_active = Column(Boolean, default=True)
    roles = relationship("Role", secondary=user_roles)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    permissions = relationship("Permission", secondary=role_permissions)

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

Base.metadata.create_all(bind=engine)

# --- 3. ИНИЦИАЛИЗАЦИЯ ТЕСТОВЫХ ДАННЫХ ---
def init_db():
    db = SessionLocal()
    if not db.query(Role).first():
        p_view = Permission(name="view_resource")
        p_edit = Permission(name="edit_rules")
        admin_role = Role(name="admin", permissions=[p_view, p_edit])
        user_role = Role(name="user", permissions=[p_view])
        db.add_all([
            User(email="admin@test.com", roles=[admin_role]),
            User(email="user@test.com", roles=[user_role])
        ])
        db.commit()
    db.close()

init_db()

# --- 4. СИСТЕМА ПРОВЕРКИ ПРАВ (БЭКЕНД) ---
app = FastAPI()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_current_user(request: Request, db: Session = Depends(get_db)):
    # Имитация: берем email из заголовка X-User-Email
    user_email = request.headers.get("X-User-Email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Необходима авторизация")
    user = db.query(User).filter(User.email == user_email, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user

def check_permission(required_perm: str):
    def decorator(user: User = Depends(get_current_user)):
        user_perms = {p.name for role in user.roles for p in role.permissions}
        if required_perm not in user_perms:
            raise HTTPException(status_code=403, detail="Доступ запрещен (Forbidden)")
        return user
    return decorator

# --- 5. МOСK-ОБЪЕКТЫ БИЗНЕС-ПРИЛОЖЕНИЯ ---
MOCK_PROJECTS = [{"id": 1, "title": "Секретный проект", "budget": "1M$"}]
MOCK_SALARIES = [{"employee": "Иван", "salary": "100k"}]

@app.get("/business/projects")
def get_projects(user: User = Depends(check_permission("view_resource"))):
    return {"user": user.email, "projects": MOCK_PROJECTS}

@app.get("/business/salaries")
def get_salaries(user: User = Depends(check_permission("edit_rules"))):
    return {"admin": user.email, "salaries": MOCK_SALARIES}
