from fastapi import FastAPI
from .api.endpoints import auth, users, passwords, folders
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Password Manager")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(passwords.router, prefix="/passwords", tags=["passwords"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(folders.router, prefix="/folders", tags=["Folders"])

app.add_middleware(
    CORSMiddleware,
    # allow_origins=["http://127.0.0.1:3000"],
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)