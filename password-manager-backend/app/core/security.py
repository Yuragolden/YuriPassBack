from fastapi import Depends, APIRouter, HTTPException
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from ..db import models
from ..db.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from starlette import status

# Конфигурация для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Секретный ключ для JWT
SECRET_KEY = "lkadsjfkal0-1238-1284odhsgoh89ayf92shgohgowqeihfaf"  # Замените на более сложный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def verify_token(token: str, db: AsyncSession):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if is_token_revoked(db, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
async def get_current_user( db: AsyncSession, user_id: int):
    # Получаем декодированную полезную нагрузку из токена
    if user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    result = await db.execute(select(models.User).filter(models.User.id == int(user_id)))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Хэширование пароля
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Создание JWT-токена
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now().replace(microsecond=0) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def is_token_revoked(db: AsyncSession, token: str) -> bool:
    result = await db.execute(select(models.RevokedToken).filter(models.RevokedToken.token == token))
    return result.scalar() is not None