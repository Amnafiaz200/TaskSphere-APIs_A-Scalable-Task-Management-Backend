# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

import models, schemas, auth
from database import SessionLocal, engine

# Create the database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Task Management API")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def home():
    return {"message": "Task Manager API is online. Visit /docs for Swagger UI."}

# --- 1. USER AUTHENTICATION ---

@app.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check for existing email/username
    existing_user = db.query(models.User).filter(
        (models.User.email == user.email) | (models.User.username == user.username)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")
    
    hashed_pwd = auth.hash_password(user.password)
    new_user = models.User(
        username=user.username, 
        email=user.email, 
        password_hash=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == user_credentials.username).first()
    
    if not user or not auth.verify_password(user_credentials.password, user.password_hash):
        raise HTTPException(status_code=403, detail="Invalid Credentials")
        
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 2. TASK MANAGEMENT (PROTECTED) ---

@app.post("/tasks", response_model=schemas.TaskOut)
def create_task(
    task: schemas.TaskCreate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_user)
):
    new_task = models.Task(**task.dict(), user_id=current_user.id)
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task

@app.get("/tasks", response_model=List[schemas.TaskOut])
def get_user_tasks(
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_user)
):
    return db.query(models.Task).filter(models.Task.user_id == current_user.id).all()

# --- 3. UPDATE & DELETE TASKS ---

@app.put("/tasks/{task_id}", response_model=schemas.TaskOut)
def update_task(
    task_id: int, 
    updated_task: schemas.TaskCreate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_user)
):
    task_query = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id)
    task = task_query.first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized")
    
    task_query.update(updated_task.dict(), synchronize_session=False)
    db.commit()
    return task_query.first()

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(auth.get_current_user)
):
    task_query = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id)
    task = task_query.first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized")
    
    task_query.delete(synchronize_session=False)
    db.commit()
    return None