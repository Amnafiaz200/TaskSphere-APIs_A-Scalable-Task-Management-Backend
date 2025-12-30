from pydantic import BaseModel, EmailStr
from typing import List, Optional

# --- Task Schemas ---
class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "pending"

class TaskCreate(TaskBase):
    pass  # Used when creating a task

class TaskOut(TaskBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True  # Allows Pydantic to read SQLAlchemy models

# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str  # Only used during registration

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(UserBase):
    id: int
    # We don't include password_hash here for security!

    class Config:
        from_attributes = True

# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None