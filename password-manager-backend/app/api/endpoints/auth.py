from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from ...db.models import User
from ...db.database import get_db
from ...schemas.auth import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from ...core.security import hash_password, create_access_token
from ...db.crud import authenticate_user
from sqlalchemy.future import select

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register_user(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Проверка, существует ли пользователь с таким email
    query = select(User).filter(User.email == request.email)
    result = await db.execute(query)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Хэширование пароля
    hashed_password = hash_password(request.password)

    # Создание нового пользователя
    new_user = User(email=request.email, password=hashed_password, username=request.username)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return RegisterResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        message="User successfully registered"
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
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
