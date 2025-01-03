import base64
import json
import string
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from ...db import crud, schemas, models
from ...db.database import get_db
from ...db.models import Password, User
from ...db.schemas import PasswordUpdate
from ...core.crypto import encrypt_data, decrypt_master_password, decrypt_data
from datetime import datetime
import random

import logging

# Инициализация логера
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


router = APIRouter()

async def get_master_password(user_id: int, db: AsyncSession) -> str:
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalars().first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Десериализация зашифрованного мастер-пароля из базы данных
    encrypted_master_password = json.loads(json.loads(user.master_password))


    # Преобразование строковых значений обратно в байты
    encrypted_master_password["ciphertext"] = base64.b64decode(encrypted_master_password["ciphertext"])
    encrypted_master_password["nonce"] = base64.b64decode(encrypted_master_password["nonce"])
    encrypted_master_password["salt"] = base64.b64decode(encrypted_master_password["salt"])

    # Дешифровка мастер-пароля
    decrypted_master_password = decrypt_master_password(encrypted_master_password)

    return decrypted_master_password

#создать пароль
@router.post("/create/{user_id}", response_model=schemas.Password)
async def create_password(password: schemas.PasswordCreate, user_id: int, db: AsyncSession = Depends(get_db)):
    print(f"Полученные данные: {password.model_dump()}")

    # Получаем пользователя из базы данных, чтобы извлечь его мастер-пароль
    user = await crud.get_user_by_id(user_id, db)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверяем, существует ли уже пароль с таким же названием
    db_password = await crud.get_password_by_name(db, name=password.name, user_id=user_id)
    if db_password:
        raise HTTPException(status_code=400, detail="Пароль с этим названием уже существует")

    # Десериализация зашифрованного мастер-пароля из JSON
    try:
        encrypted_master_password = json.loads(json.loads(user.master_password))

        ciphertext = base64.b64decode(encrypted_master_password["ciphertext"])
        nonce = base64.b64decode(encrypted_master_password["nonce"])
        salt = base64.b64decode(encrypted_master_password["salt"])

        # Расшифровка мастер-пароля
        decrypted_master_password = decrypt_master_password(
            {"ciphertext": ciphertext, "nonce": nonce, "salt": salt}
        )
        print(f"Дешифрованный мастер-пароль: {decrypted_master_password}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Ошибка при дешифровке мастер-пароля")


    # Шифруем данные (логин, комментарий и пароль) с использованием расшифрованного мастер-пароля
    encrypted_login = encrypt_data(password.login, decrypted_master_password)
    encrypted_comment = encrypt_data(password.comment, decrypted_master_password)
    encrypted_password = encrypt_data(password.password, decrypted_master_password)


    # Создаем запись о пароле с зашифрованными данными
    try:
        db_password = await crud.create_password(
            db=db,
            password=schemas.PasswordCreate(
                user_id=user_id,
                name=password.name,
                login=encrypted_login,
                password=encrypted_password,
                url=password.url,
                comment=encrypted_comment,
                folder_id=password.folder_id,
                created_at=password.created_at or datetime.now().replace(microsecond=0)
            )
        )
        return db_password
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при создании пароля: {str(e)}")


#сгенерировать новый пароль
@router.post("/generate")
async def generate_password():
    length = 15
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(1, length))
    return password

#получить определенный пароль(админ)
@router.get("/{password_id}", response_model=schemas.Password)
async def get_password(password_id: int, user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()

    if password is None:
        raise HTTPException(status_code=404, detail="Password not found")

    # Получаем мастер-пароль пользователя из базы данных
    master_password = await get_master_password(user_id, db)

    # Расшифровываем данные пароля
    decrypted_login = decrypt_data(password.login, master_password)
    decrypted_password = decrypt_data(password.password, master_password)
    decrypted_comment = decrypt_data(password.comment, master_password)

    return {
        "name": password.name,
        "login": decrypted_login,
        "password": decrypted_password,
        "created_at": password.created_at,
        "updated_at": password.updated_at,
        "comment": decrypted_comment,
        "url": password.url,
        "folder_id": password.folder_id,
    }


# Обновление пароля
@router.put("/{password_id}")
async def update_password(password_id: int, password_update: PasswordUpdate, db: AsyncSession = Depends(get_db)):
    # Получаем запись из базы данных
    result = await db.execute(select(Password).filter(Password.id == password_id))
    password = result.scalars().first()
    user_id = password.user_id


    if not password:
        raise HTTPException(status_code=404, detail="Password not found")

    # Получаем мастер-пароль пользователя
    master_password = await get_master_password(user_id, db)

    # Обновляем поля, если они присутствуют в запросе
    if password_update.name is not None:
        password.name = password_update.name
    if password_update.login is not None:
        password.login = encrypt_data(password_update.login, master_password)  # Шифруем логин
    if password_update.password is not None:
        password.password = encrypt_data(password_update.password, master_password)  # Шифруем пароль
    if password_update.url is not None:
        password.url = password_update.url
    if password_update.comment is not None:
        password.comment = encrypt_data(password_update.comment, master_password)  # Шифруем комментарий

    # Обновляем метку времени
    password.updated_at = datetime.now().replace(microsecond=0)

    # Сохраняем изменения в базе данных
    db.add(password)
    await db.commit()
    await db.refresh(password)

    # Формируем и возвращаем ответ
    return {
        "id": password.id,
        "name": password.name,
        "login": password_update.login,
        "password": password_update.password,
        "updated_at": password.updated_at,
        "comment": password_update.comment,
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
async def get_folder_passwords(folder_id: int, user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.folder_id == folder_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this folder")
    master_password = await get_master_password(user_id, db)

    # Дешифруем данные для каждого пароля
    for password in passwords:
        try:
            password.login = decrypt_data(password.login, master_password)
            password.password = decrypt_data(password.password, master_password)
            password.comment = decrypt_data(password.comment, master_password)
        except HTTPException as e:
            logger.error(f"Decryption failed for user {user_id}, folder {folder_id}: {str(e)}")
            raise e

    return passwords


#получить все пароли пользователя без папки
@router.get("/folders/unlisted/{user_id}", response_model=List[schemas.Password])
async def get_unlisted_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.folder_id.is_(None)))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this user")

    # Получаем мастер-пароль
    master_password = await get_master_password(user_id, db)

    # Дешифруем данные для каждого пароля
    for password in passwords:
        try:
            password.login = decrypt_data(password.login, master_password)
            password.password = decrypt_data(password.password, master_password)
            password.comment = decrypt_data(password.comment, master_password)
        except HTTPException as e:
            logger.error(f"Decryption failed for user {user_id}, folder {None}: {str(e)}")
            raise e

    return passwords



#получить все пароли определенного пользователя
@router.get("/user/{user_id}", response_model=List[schemas.Password])
async def get_user_passwords(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Passwords not found for this user")

    # Получаем мастер-пароль
    master_password = await get_master_password(user_id, db)

    # Дешифруем данные для каждого пароля
    for password in passwords:
        password.login = decrypt_data(password.login, master_password)
        password.password = decrypt_data(password.password, master_password)
        password.comment = decrypt_data(password.comment, master_password)

    return passwords


#получить конкретный пароль конкретного пользователя
@router.get("/user/{user_id}/{password_id}", response_model=List[schemas.Password])
async def get_user_password_byId(user_id: int, password_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Password).filter(Password.user_id == user_id).filter(Password.id == password_id))
    passwords = result.scalars().all()

    if not passwords:
        raise HTTPException(status_code=404, detail="Password not found for this user")

    # Получаем мастер-пароль
    master_password = await get_master_password(user_id, db)
    print(passwords)
    # Дешифруем данные для конкретного пароля
    password = passwords[0]
    print(password)
    password.login = decrypt_data(password.login, master_password)
    password.password = decrypt_data(password.password, master_password)
    password.comment = decrypt_data(password.comment, master_password)

    return [password]  # Возвращаем пароль в списке, так как это response_model=List[schemas.Password]
