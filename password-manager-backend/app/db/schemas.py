from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    message: str

    class Config:
        orm_mode = True

class LoginRequest(BaseModel):
    username: str
    password: str
    class Config:
        orm_mode = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    class Config:
        orm_mode = True


class RegisterResponse(BaseModel):
    id: int
    username: str
    email: str
    message: str

    class Config:
        orm_mode = True

class Password(BaseModel):
    id: int
    user_id: int
    name: str
    login: str
    password: str
    url: Optional[str] = None
    folder_id: Optional[int] = None
    comment: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

class PasswordCreate(BaseModel):
    user_id: int
    name: str
    login: str
    password: str
    url: Optional[str] = None
    folder_id: Optional[int] = None
    comment: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        orm_mode = True

class PasswordUpdate(BaseModel):
    name: Optional[str]
    login: Optional[str]
    password: Optional[str]
    folder_id: Optional[int]
    url: Optional[str]
    comment: Optional[str]
    updated_at: Optional[datetime] = None


    class Config:
        orm_mode = True


class FolderCreate(BaseModel):
    name: str

    class Config:
        orm_mode = True

# Схема для отображения папки
class Folder(FolderCreate):
    id: int

    class Config:
        orm_mode = True
