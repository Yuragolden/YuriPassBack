import base64

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from ...db.models import CompanyUser, Password, User
from ...db.schemas import PasswordCreate, PasswordResponse, Password as Password1
from ...db.database import get_db
from ...core.crypto import encrypt_data, decrypt_master_password, decrypt_data
from ...core.security import get_current_user
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

async def is_admin_for_user(db: AsyncSession, admin_id: int, target_user_id: int) -> bool:
    # Проверяем, является ли текущий пользователь администратором
    logger.info(f"Проверка прав администратора: admin_id={admin_id}, user_id={target_user_id}")
    admin_query = await db.execute(
        select(CompanyUser).where(
            CompanyUser.user_id == admin_id,
            CompanyUser.role == "admin"
        )
    )
    admin = admin_query.scalars().first()

    if not admin:
        return False  # Не администратор

    # Проверяем, относится ли целевой пользователь к той же компании
    target_user_query = await db.execute(
        select(CompanyUser).where(CompanyUser.user_id == target_user_id)
    )
    target_user = target_user_query.scalars().first()

    if not target_user:
        return False  # Пользователь не найден

    # Проверяем, совпадают ли `company_id` у администратора и пользователя
    return admin.company_id == target_user.company_id

@router.post("/passwords/admin-add/", response_model=PasswordResponse, status_code=status.HTTP_201_CREATED)
async def admin_add_password(
    user_email: str,
    admin_id:int,
    password_data: PasswordCreate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Найти пользователя по email
    target_user_query = await db.execute(
        select(User).where(User.email == user_email)
    )
    target_user = target_user_query.scalars().first()

    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден.")

    admin_user_query = await db.execute(select(User).where(User.id == admin_id))
    admin_user = admin_user_query.scalars().first()

    # Логика проверки прав администратора
    current_user = await get_current_user(db, admin_id)
    print("current_user")
    print(current_user.id)

    is_admin = await is_admin_for_user(db, current_user.id, target_user.id)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Вы не являетесь администратором или пользователь не относится к вашей компании."
        )

    try:
        encrypted_master_password_user = json.loads(json.loads(target_user.master_password))

        ciphertext = base64.b64decode(encrypted_master_password_user["ciphertext"])
        nonce = base64.b64decode(encrypted_master_password_user["nonce"])
        salt = base64.b64decode(encrypted_master_password_user["salt"])

        # Расшифровка
        decrypted_master_password_user = decrypt_master_password(
            {"ciphertext": ciphertext, "nonce": nonce, "salt": salt}
        )

        encrypted_master_password_admin = json.loads(json.loads(admin_user.master_password))

        ciphertext_admin = base64.b64decode(encrypted_master_password_admin["ciphertext"])
        nonce_admin = base64.b64decode(encrypted_master_password_admin["nonce"])
        salt_admin = base64.b64decode(encrypted_master_password_admin["salt"])

        # Расшифровка
        decrypted_master_password_admin = decrypt_master_password(
            {"ciphertext": ciphertext_admin, "nonce": nonce_admin, "salt": salt_admin}
        )

        # if password_data.folder_id in admin_user.f

    except json.JSONDecodeError as e:
        logger.error(f"Ошибка парсинга мастер-пароля: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Некорректный формат мастер-пароля."
        )
    except Exception as e:
        logger.error(f"Ошибка расшифровки мастер-пароля: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось расшифровать мастер-пароль пользователя."
        )

    encrypted_login_user = encrypt_data(password_data.login, decrypted_master_password_user)
    encrypted_comment_user = (
        encrypt_data(password_data.comment, decrypted_master_password_user)
        if password_data.comment else None
    )
    encrypted_password_user = encrypt_data(password_data.password, decrypted_master_password_user)


    encrypted_login_admin = encrypt_data(password_data.login, decrypted_master_password_admin)
    encrypted_comment_admin = (
        encrypt_data(password_data.comment, decrypted_master_password_admin)
        if password_data.comment else None
    )
    encrypted_password_admin = encrypt_data(password_data.password, decrypted_master_password_admin)

    # Создаём запись пароля
    new_password = Password(
        user_id=target_user.id,  # Убедитесь, что используется правильный ID
        name=password_data.name,
        login=encrypted_login_user,
        password=encrypted_password_user,
        url=password_data.url,
        folder_id=password_data.folder_id,
        comment=encrypted_comment_user,
        created_at=datetime.now().replace(microsecond=0),
    )
    new_password_admin = Password(
        user_id=admin_user.id,  # Убедитесь, что используется правильный ID
        name=password_data.name,
        login=encrypted_login_admin,
        password=encrypted_password_admin,
        url=password_data.url,
        folder_id=password_data.folder_id,
        comment=encrypted_comment_admin,
        created_at=datetime.now().replace(microsecond=0),
    )
    db.add(new_password)
    db.add(new_password_admin)
    await db.commit()
    await db.refresh(new_password)
    await db.refresh(new_password_admin)


    return {"message": "Пароль успешно добавлен", "password_id": new_password.id}
