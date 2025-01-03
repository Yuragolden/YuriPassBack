from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, DateTime
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime

Base = declarative_base()

# Таблица пользователей
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)  # Добавляем имя пользователя
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    last_login = Column(DateTime, default=datetime.utcnow)
    folders = relationship("Folder", back_populates="user")
    master_password = Column(JSON, nullable=False)


# Таблица паролей
class Password(Base):
    __tablename__ = 'passwords'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    folder_id = Column(Integer, ForeignKey('folders.id'), nullable=True)
    name = Column(String, nullable=False)
    login = Column(String, nullable=False)
    password = Column(String, nullable=False)
    url = Column(String, nullable=True)
    comment = Column(String, nullable=True)
    # is_favorite = Column(Boolean, default=False)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

# Таблица папок
class Folder(Base):
    __tablename__ = 'folders'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String, nullable=False)

    user = relationship("User", back_populates="folders")


# Таблица корзины
class Trash(Base):
    __tablename__ = 'trash'

    id = Column(Integer, primary_key=True, index=True)
    password_id = Column(Integer, ForeignKey('passwords.id'))
    deleted_at = Column(DateTime, default=datetime.utcnow)

# Таблица компаний
class Company(Base):
    __tablename__ = 'companies'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now().replace(microsecond=0))


# Таблица пользователей компаний
class CompanyUser(Base):
    __tablename__ = 'company_users'

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey('companies.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    role = Column(String, nullable=False)
