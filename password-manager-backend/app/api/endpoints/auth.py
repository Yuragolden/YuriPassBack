from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from ...db.models import User
from ...db.database import get_db
from ...schemas.auth import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from ...core.security import hash_password, create_access_token
from ...core.crypto import decrypt_master_password, encrypt_master_password
from ...db.crud import authenticate_user
from sqlalchemy.future import select
import json
import base64

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register_user(request: RegisterRequest, db: AsyncSession = Depends(get_db)):

    query = select(User).filter(User.email == request.email)
    result = await db.execute(query)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Хэширование пароля
    hashed_password = hash_password(request.password)

    encrypted_master_password = encrypt_master_password(request.master_password)

    encrypted_master_password_dict = json.loads(encrypted_master_password)

    # Сериализация для сохранения в базу данных
    encrypted_master_password_serialized = json.dumps({
        "ciphertext": encrypted_master_password_dict["ciphertext"],
        "nonce": encrypted_master_password_dict["nonce"],
        "salt": encrypted_master_password_dict["salt"]
    })

    # Создание нового пользователя
    new_user = User(email=request.email, password=hashed_password, username=request.username, master_password=encrypted_master_password_serialized)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return RegisterResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        message="Пользователь успешно зарегистрирован"
    )

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(login_request: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, login_request.username, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        # Расшифровка мастер-пароля
    try:
        # Десериализация зашифрованного мастер-пароля из JSON
        encrypted_master_password = json.loads(json.loads(user.master_password))

        ciphertext = base64.b64decode(encrypted_master_password["ciphertext"])
        nonce = base64.b64decode(encrypted_master_password["nonce"])
        salt = base64.b64decode(encrypted_master_password["salt"])

        # Расшифровка
        decrypted_master_password = decrypt_master_password(
            {"ciphertext": ciphertext, "nonce": nonce, "salt": salt}
        )

        print(decrypted_master_password)

        # Проверка совпадения расшифрованного мастер-пароля
        if decrypted_master_password != login_request.master_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect master password",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password",
            headers={"WWW-Authenticate": "Bearer"},
        )



    access_token = create_access_token(data={"sub": user.username, "userId": user.id })
    return {"access_token": access_token, "token_type": "bearer"}








