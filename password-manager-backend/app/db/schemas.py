from pydantic import BaseModel
from typing import Optional
from datetime import datetime

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
        from_attributes = True

class PasswordCreate(BaseModel):
    user_id: Optional[int] = 0
    name: str
    login: str
    password: str
    url: Optional[str] = None
    folder_id: Optional[int] = None
    comment: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class PasswordUpdate(BaseModel):
    name: Optional[str]
    login: Optional[str]
    password: Optional[str]
    folder_id: Optional[int]
    url: Optional[str]
    comment: Optional[str]
    updated_at: Optional[datetime] = None


    class Config:
        from_attributes = True


class FolderCreate(BaseModel):
    name: str

    class Config:
        from_attributes = True

# Схема для отображения папки
class Folder(FolderCreate):
    id: int
    user_id: int

    class Config:
        from_attributes = True

class Company(BaseModel):
    id: int
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


class CompanyUser(BaseModel):
    id: int
    email: str
    company_id: int

    class Config:
        from_attributes = True

class PasswordResponse(BaseModel):
    message: str
    password_id: int