from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from starlette.responses import JSONResponse

from ...db import models, schemas
from ...db.database import get_db
from ...core.security import get_current_user

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Проверяем, существует ли пользователь с таким ID
# result = await db.execute(select(models.User).filter(models.User.id == folder.user_id))
# user = result.scalars().first()
# if not user:
#     raise HTTPException(status_code=404, detail="User not found")
#

# Маршрут для создания новой папки
@router.post("/", response_model=schemas.Folder)
async def create_folder(folder: schemas.FolderCreate, db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user = await get_current_user(db, token)
    print(user)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Создаем папку с привязкой к текущему пользователю
    db_folder = models.Folder(name=folder.name, user_id=user.id)
    print('дура работай')
    # db_folder = models.Folder(name=folder.name, user_id=3)
    db.add(db_folder)
    await db.commit()
    await db.refresh(db_folder) # Логика сохранения
    return JSONResponse(status_code=201, content={"id": db_folder.id})

    # return db_folder


# Маршрут для получения всех папок
@router.get("/", response_model=List[schemas.Folder])
async def get_folders(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Folder))
    db_folders = result.scalars().all()
    return db_folders

# Маршрут для получения одной папки по ID
@router.get("/{folder_id}", response_model=schemas.Folder)
async def get_folder(folder_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Folder).filter(models.Folder.id == folder_id))
    db_folder = result.scalars().first()
    if db_folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")
    return db_folder

# Маршрут для удаления папки
@router.delete("/{folder_id}", status_code=204)
async def delete_folder(folder_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Folder).filter(models.Folder.id == folder_id))
    db_folder = result.scalars().first()
    if db_folder is None:
        raise HTTPException(status_code=404, detail="Folder not found")
    await db.delete(db_folder)
    await db.commit()
    return {"message": "Folder deleted successfully"}


