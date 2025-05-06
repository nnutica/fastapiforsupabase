from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import os
import requests
import uuid
from datetime import datetime
import bcrypt

# โหลด .env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE")

app = FastAPI()

# ==== MODELS ====

class UserCreate(BaseModel):
    Username: str
    Email: EmailStr
    Password: str

class UserOut(BaseModel):
    Userid: str
    Username: str
    Email: EmailStr
    Created_at: str

# ==== HELPERS ====

def supabase_headers():
    return {
        "apikey": SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type": "application/json"
    }

def supabase_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# ==== ROUTES ====

@app.post("/register", response_model=UserOut)
def register_user(user: UserCreate):
    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    hashed_password = hash_password(user.Password)

    payload = {
        "Userid": user_id,
        "Username": user.Username,
        "Email": user.Email,
        "Password": hashed_password,
        "Created_at": created_at
    }

    res = requests.post(
        supabase_url(SUPABASE_TABLE),
        headers=supabase_headers(),
        json=payload
    )

    if res.status_code != 201:
        raise HTTPException(status_code=400, detail=res.text)

    return UserOut(
        Userid=user_id,
        Username=user.Username,
        Email=user.Email,
        Created_at=created_at
    )

@app.get("/users", response_model=list[UserOut])
def get_users():
    res = requests.get(
        supabase_url(SUPABASE_TABLE),
        headers=supabase_headers()
    )

    if res.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch users")

    data = res.json()
    return [
        UserOut(
            Userid=user["Userid"],
            Username=user["Username"],
            Email=user["Email"],
            Created_at=user["Created_at"]
        ) for user in data
    ]

@app.get("/users/{user_id}", response_model=UserOut)
def get_user_by_id(user_id: str):
    url = f"{supabase_url(SUPABASE_TABLE)}?Userid=eq.{user_id}"
    res = requests.get(url, headers=supabase_headers())

    data = res.json()
    if not data:
        raise HTTPException(status_code=404, detail="User not found")

    user = data[0]
    return UserOut(
        Userid=user["Userid"],
        Username=user["Username"],
        Email=user["Email"],
        Created_at=user["Created_at"]
    )

@app.delete("/users/{user_id}")
def delete_user(user_id: str):
    url = f"{supabase_url(SUPABASE_TABLE)}?Userid=eq.{user_id}"
    res = requests.delete(url, headers=supabase_headers())

    if res.status_code not in [200, 204]:
        raise HTTPException(status_code=400, detail="Delete failed")
    
    return {"message": "User deleted"}

print("API KEY:", SUPABASE_API_KEY)
print("URL:", SUPABASE_URL)
