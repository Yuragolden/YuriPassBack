from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from . import models, schemas
import bcrypt
from passlib.context import CryptContext
from .models import User, Password
from datetime import datetime


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def authenticate_user(db: AsyncSession, username: str, password: str):
    query = select(User).where(User.username == username)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        return None
    if not pwd_context.verify(password, user.password):
        return None
    return user


# Хеширование пароля
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    print(bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8'))
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

async def create_password(db: AsyncSession, password: schemas.PasswordCreate):

    if not password.created_at:
        password.created_at = datetime.now().replace(microsecond=0)
        print(password.created_at.replace(microsecond=0))

    db_password = Password(
        user_id=password.user_id,
        name=password.name,
        login=password.login,
        password=password.password,
        url=password.url,
        comment=password.comment,
        folder_id=password.folder_id,
        created_at = password.created_at,
    )

    db.add(db_password)
    await db.commit()
    await db.refresh(db_password)

    return db_password


async def get_user_by_id(user_id: int, db: AsyncSession):
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def get_password_by_id(db: AsyncSession, password_id: int):
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()
    if password is None:
        raise HTTPException(status_code=404, detail="Password not found")
    return password


async def get_password_by_name(db: AsyncSession, name: str, user_id: int):
    result = await db.execute(select(Password).filter(Password.name == name).filter(Password.user_id == user_id))
    return result.scalars().first()  # Возвращает первый результат или None


async def get_passwords(db: AsyncSession):
    result = await db.execute(select(models.Password))
    return result.scalars().all()



async def update_password(db: AsyncSession, password_id: int, password: schemas.PasswordCreate):
    async with db.begin():
        db_password = await get_password_by_id(db, password_id)
        if db_password:
            db_password.name = password.name
            # db_password.password = password.password
            db_password.password = hash_password(password.password)
            db_password.updated_at = db_password.updated_at.datetime.now().replace(microsecond=0)
            await db.flush()
        return db_password


async def delete_password(db: AsyncSession, password_id: int):
    # Получаем запись по ID
    db_password = await get_password_by_id(db, password_id)
    if not db_password:
        raise HTTPException(status_code=404, detail="Password not found")

    # Создаем копию данных для возврата
    response_data = {
        "id": db_password.id,
        "user_id": db_password.user_id,
        "name": db_password.name,
        "login": db_password.login,
        "password": db_password.password,
        "created_at": db_password.created_at,
        "updated_at": db_password.updated_at,
        "comment": db_password.comment,
        "url": db_password.url,
        "folder_id": db_password.folder_id,
    }

    # Удаляем запись
    await db.delete(db_password)
    await db.commit()

    # Возвращаем данные удаленного объекта
    return response_data


