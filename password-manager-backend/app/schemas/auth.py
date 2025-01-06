from pydantic import BaseModel, EmailStr

# Схема для входящих данных регистрации
class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    master_password: str
    class Config:
        from_attributes = True

# Схема для ответа при успешной регистрации
class RegisterResponse(BaseModel):
    id: int
    email: str
    username: str
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str
    master_password: str
    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    is_admin: bool
    class Config:
        from_attributes = True

class LogOutRequest(BaseModel):
    token: str
    class Config:
        from_attributes = True

class LogOutResponse(BaseModel):
    message: str
    class Config:
        from_attributes = True