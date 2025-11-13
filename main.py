# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import databases
import sqlalchemy

DATABASE_URL = "postgresql://username:password@HOST:PORT/dbname"  # set via env var in Render
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password_hash", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

device_data = sqlalchemy.Table(
    "device_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
    sqlalchemy.Column("payload", sqlalchemy.JSON),
)

engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

app = FastAPI(title="Seizure Monitor Backend")

# auth
SECRET_KEY = "CHANGE_THIS_SECRET"   # put a secure env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user_by_username(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user:
        return False
    if not verify_password(password, user["password_hash"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/api/register", response_model=dict)
async def register(u: UserCreate):
    existing = await get_user_by_username(u.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username exists")
    query = users.insert().values(username=u.username, password_hash=get_password_hash(u.password), is_admin=u.is_admin)
    user_id = await database.execute(query)
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(form_data: UserCreate):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": user["username"], "is_admin": user["is_admin"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

# Endpoint for ESP32 devices to POST sensor data (no auth or simple API key option)
class DevicePayload(BaseModel):
    device_id: str
    timestamp_ms: int
    sensors: dict
    seizure_flag: bool = False

@app.post("/api/devices/data")
async def receive_device_data(payload: DevicePayload):
    ts = datetime.utcfromtimestamp(payload.timestamp_ms/1000.0)
    q = device_data.insert().values(device_id=payload.device_id, timestamp=ts, payload=payload.dict())
    row_id = await database.execute(q)
    return {"status": "ok", "id": row_id}

# User endpoint to fetch device data (requires login)
@app.get("/api/devices/{device_id}", response_model=List[dict])
async def get_device_history(device_id: str, current_user: dict = Depends(get_current_user)):
    q = device_data.select().where(device_data.c.device_id == device_id).order_by(device_data.c.timestamp.desc()).limit(1000)
    rows = await database.fetch_all(q)
    return [{"id": r["id"], "device_id": r["device_id"], "timestamp": r["timestamp"].isoformat(), "payload": r["payload"]} for r in rows]

# Admin-only: list users
@app.get("/api/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    q = users.select()
    rows = await database.fetch_all(q)
    return [{"id": r["id"], "username": r["username"], "is_admin": r["is_admin"]} for r in rows]
