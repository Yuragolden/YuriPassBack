import json

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from ...db import crud, schemas, models
from ...db.database import get_db
from ...db.models import Password
from ...db.schemas import PasswordUpdate
from ...db.crud import hash_password, get_user_passwords, get_folder_passwords
from datetime import datetime

router = APIRouter()

@router.post("/create", response_model=schemas.Password)
async def create_password(password: schemas.PasswordCreate, db: AsyncSession = Depends(get_db)):
    print(f"Полученные данные: {password.dict()}")
    db_password = await crud.get_password_by_name(db, name=password.name)
    if db_password:
        raise HTTPException(status_code=400, detail="Пароль с этим названием уже существует")
    try:
        db_password = await crud.create_password(db=db, password=password)
        return db_password
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при создании пароля: {str(e)}")


@router.get("/{password_id}", response_model=schemas.Password)
async def get_password(password_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()

    if password is None:
        raise HTTPException(status_code=404, detail="Password not found")

    password.created_at = password.created_at.strftime('%Y-%m-%d')
    password.updated_at = password.updated_at.strftime('%Y-%m-%d')

    return password

@router.put("/{password_id}")
async def update_password(password_id: int, password_update: PasswordUpdate, db: AsyncSession = Depends(get_db)):
    # Используем асинхронный запрос для получения пароля
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()

    if not password:
        raise HTTPException(status_code=404, detail="Password not found")

    # Обновляем только те поля, которые были переданы в запросе
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
    if password_update.is_favorite is not None:
        password.is_favorite = password_update.is_favorite

    password.updated_at = datetime.utcnow()  # Обновляем время

    db.add(password)
    await db.commit()
    await db.refresh(password)

    return {
        "name": password.name,
        "login": password.login,
        "password": password.password,
        "created_at": password.created_at.strftime('%Y-%m-%d'),
        "updated_at": password.updated_at.strftime('%Y-%m-%d')
    }

# @router.get("/", response_model=List[schemas.Password])
# async def list_passwords(db: AsyncSession = Depends(get_db)):
#     return await crud.get_passwords(db)
@router.get("/", response_model=List[schemas.Password])
async def list_passwords(db: AsyncSession = Depends(get_db)):
    passwords = await crud.get_passwords(db)
    # return {"passwords": passwords}
    return passwords

@router.delete("/{password_id}", response_model=schemas.Password)
async def delete_password(password_id: int, db: AsyncSession = Depends(get_db)):
    db_password = await crud.get_password_by_id(db, password_id=password_id)
    if db_password is None:
        raise HTTPException(status_code=404, detail="Password not found")
    return await crud.delete_password(db, password_id=password_id)


#маршруты для получения паролей пользователя
@router.get("/folder/{user_id}/{folder_id}", response_model=List[schemas.Password])
async def get_folder_passwords(folder_id: int,user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.folder_id == folder_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this folder")

    for password in passwords:
        password.created_at = password.created_at.strftime('%Y-%m-%d')
        password.updated_at = password.updated_at.strftime('%Y-%m-%d')

    return passwords
@router.get("/user/{user_id}", response_model=List[schemas.Password])
async def get_user_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this user")

    # for password in passwords:
    #     password.created_at = password.created_at.strftime('%Y-%m-%d')
    #     password.updated_at = password.updated_at.strftime('%Y-%m-%d')

    return passwords