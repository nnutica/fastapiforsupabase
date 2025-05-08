from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from jose import JWTError, jwt
import os, requests, uuid, bcrypt
from datetime import datetime, timedelta

# ==== โหลด ENV ====
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ==== FastAPI App ====
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ==== Models ====
class UserCreate(BaseModel):
    Username: str
    Email: EmailStr
    Password: str

class UserLogin(BaseModel):
    Email: EmailStr
    Password: str

class UserOut(BaseModel):
    Userid: str
    Username: str
    Email: EmailStr
    Created_at: str

# ==== Helper Functions ====
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
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    data.update({"exp": expire})
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def get_user_by_email(email: str):
    url = f"{supabase_url(SUPABASE_TABLE)}?Email=eq.{email}"
    res = requests.get(url, headers=supabase_headers())
    data = res.json()
    return data[0] if data else None

def get_current_user(token: str = Depends(oauth2_scheme)) -> UserOut:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserOut(
        Userid=user["Userid"],
        Username=user["Username"],
        Email=user["Email"],
        Created_at=user["Created_at"]
    )

# ==== Routes ====

@app.post("/register", response_model=UserOut)
def register(user: UserCreate):
    if get_user_by_email(user.Email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    hashed_pw = hash_password(user.Password)

    payload = {
        "Userid": user_id,
        "Username": user.Username,
        "Email": user.Email,
        "Password": hashed_pw,
        "Created_at": created_at
    }

    res = requests.post(supabase_url(SUPABASE_TABLE), headers=supabase_headers(), json=payload)
    if res.status_code != 201:
        raise HTTPException(status_code=400, detail="Error creating user")

    return UserOut(
        Userid=user_id,
        Username=user.Username,
        Email=user.Email,
        Created_at=created_at
    )

@app.post("/login")
def login(credentials: UserLogin):
    user = get_user_by_email(credentials.Email)
    if not user or not verify_password(credentials.Password, user["Password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": user["Email"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "Userid": user["Userid"],
            "Username": user["Username"],
            "Email": user["Email"],
            "Created_at": user["Created_at"]
        }
    }

@app.get("/me", response_model=UserOut)
def read_current_user(current_user: UserOut = Depends(get_current_user)):
    return current_user
