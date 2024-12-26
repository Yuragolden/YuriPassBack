from pydantic import BaseModel, EmailStr

# Схема для входящих данных регистрации
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

# Схема для ответа при успешной регистрации
class RegisterResponse(BaseModel):
    id: int
    email: str
    username: str

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