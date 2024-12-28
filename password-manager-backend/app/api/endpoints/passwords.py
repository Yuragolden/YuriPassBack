import json

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy import Nullable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from ...db import crud, schemas, models
from ...db.database import get_db
from ...db.models import Password
from ...db.schemas import PasswordUpdate
from ...db.crud import hash_password
from datetime import datetime

import logging

logger = logging.getLogger("uvicorn")


router = APIRouter()

#создать пароль
@router.post("/create", response_model=schemas.Password)
async def create_password(password: schemas.PasswordCreate, db: AsyncSession = Depends(get_db)):
    print(f"Полученные данные: {password.model_dump()}")

    db_password = await crud.get_password_by_name(db, name=password.name)

    if db_password:
        raise HTTPException(status_code=400, detail="Пароль с этим названием уже существует")

    try:
        db_password = await crud.create_password(db=db, password=password)
        return db_password
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при создании пароля: {str(e)}")

#получить определенный пароль(админ)
@router.get("/{password_id}", response_model=schemas.Password)
async def get_password(password_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()

    if password is None:
        raise HTTPException(status_code=404, detail="Password not found")

    password.created_at = password.created_at.strftime('%Y-%m-%d')
    password.updated_at = password.updated_at.strftime('%Y-%m-%d')

    return password

#обновить пароль
@router.put("/{password_id}")
async def update_password(password_id: int, password_update: PasswordUpdate, db: AsyncSession = Depends(get_db)):

    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()

    if not password:
        raise HTTPException(status_code=404, detail="Password not found")


    if password_update.name:
        password.name = password_update.name
    if password_update.login:
        password.login = password_update.login
    if password_update.password:
        password.password = hash_password(password_update.password)
    if password_update.url:
        password.url = password_update.url
    if password_update.comment:
        password.comment = password_update.comment


    password.updated_at = datetime.utcnow()  # Обновляем время

    db.add(password)
    await db.commit()
    await db.refresh(password)

    return {
        "name": password.name,
        "login": password.login,
        "password": password.password,
        "created_at": password.created_at.strftime('%Y-%m-%d'),
        "updated_at": password.updated_at.strftime('%Y-%m-%d'),
        "comment": password.comment,
        "url": password.url,
        "folder_id": password.folder_id,
    }

#получить все пароли(админ)
@router.get("/", response_model=List[schemas.Password])
async def list_passwords(db: AsyncSession = Depends(get_db)):
    passwords = await crud.get_passwords(db)
    return passwords

#удалить определенный пароль
@router.delete("/{password_id}", response_model=schemas.Password)
async def delete_password(password_id: int, db: AsyncSession = Depends(get_db)):
    db_password = await crud.get_password_by_id(db, password_id=password_id)
    if db_password is None:
        raise HTTPException(status_code=404, detail="Password not found")
    return await crud.delete_password(db, password_id=password_id)


#получить все пароли пользователя в конкретной папке
@router.get("/folder/{user_id}/{folder_id}", response_model=List[schemas.Password])
async def get_folder_passwords(folder_id: int,user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.folder_id == folder_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this folder")

    return passwords

#получить все пароли пользователя без папки
@router.get("/folders/unlisted/{user_id}", response_model=List[schemas.Password])
async def get_unlisted_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.folder_id.is_(None)))

    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this folder")


    return passwords

#получить все пароли определенного пользователя
@router.get("/user/{user_id}", response_model=List[schemas.Password])
async def get_user_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this user")

    return passwords

#получить конкретный пароль конкретного пользователя
@router.get("/user/{user_id}/{password_id}", response_model=List[schemas.Password])
async def get_user_password_byId(user_id: int, password_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.id == password_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this user")

    return passwords