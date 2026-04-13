from fastapi import FastAPI, HTTPException, Depends, Request
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Table
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base

# --- НАСТРОЙКИ БД ---
Base = declarative_base()
engine = create_engine("sqlite:///./auth_system.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

# Таблицы связи многие-ко-многим
user_roles = Table('user_roles', Base.metadata,
                   Column('user_id', ForeignKey('users.id'), primary_key=True),
                   Column('role_id', ForeignKey('roles.id'), primary_key=True)
                   )

role_permissions = Table('role_permissions', Base.metadata,
                         Column('role_id', ForeignKey('roles.id'), primary_key=True),
                         Column('permission_id', ForeignKey('permissions.id'), primary_key=True)
                         )


# --- МОДЕЛИ БД ---
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
    name = Column(String, unique=True)  # например, "edit_rules"


Base.metadata.create_all(bind=engine)


# --- ИНИЦИАЛИЗАЦИЯ ТЕСТОВЫХ ДАННЫХ ---
def init_db():
    db = SessionLocal()
    if not db.query(Role).first():
        p_view = Permission(name="view_resource")
        p_admin = Permission(name="edit_rules")

        admin_role = Role(name="admin", permissions=[p_view, p_admin])
        user_role = Role(name="user", permissions=[p_view])

        u_admin = User(email="admin@test.com", roles=[admin_role])
        u_user = User(email="user@test.com", roles=[user_role])

        db.add_all([u_admin, u_user])
        db.commit()
    db.close()


init_db()

# --- ЛОГИКА ДОСТУПА ---
app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(request: Request, db: Session = Depends(get_db)):
    # Имитация получения пользователя из токена в заголовке
    user_email = request.headers.get("X-User-Email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.email == user_email, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def check_permission(required_perm: str):
    def decorator(user: User = Depends(get_current_user)):
        user_perms = {p.name for role in user.roles for p in role.permissions}
        if required_perm not in user_perms:
            raise HTTPException(status_code=403, detail="Forbidden: Insufficient permissions")
        return user

    return decorator


# --- API ЭНДПОИНТЫ ---

@app.get("/resource")
def get_resource(user: User = Depends(check_permission("view_resource"))):
    return {"data": "Это секретный ресурс", "accessed_by": user.email}


# API для Администратора: получение и изменение правил
@app.get("/admin/rules")
def get_all_rules(user: User = Depends(check_permission("edit_rules")), db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    return {role.name: [p.name for p in role.permissions] for role in roles}


@app.post("/admin/assign-role")
def assign_role(target_email: str, role_name: str,
                admin: User = Depends(check_permission("edit_rules")),
                db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == target_email).first()
    role = db.query(Role).filter(Role.name == role_name).first()

    if not user or not role:
        raise HTTPException(status_code=404, detail="User or Role not found")

    if role not in user.roles:
        user.roles.append(role)
        db.commit()
    return {"message": f"Роль {role_name} успешно выдана {target_email}"}
