from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, timezone
import sqlalchemy
import databases
import json
import os
from jose import JWTError, jwt

# =======================
# PH TIMEZONE
# =======================
PHT = timezone(timedelta(hours=8))

def now_pht():
    return datetime.now(PHT)

def from_ms_to_pht(ms: int):
    return datetime.fromtimestamp(ms / 1000.0, tz=PHT)

# =======================
# DATABASE CONFIG
# =======================
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.abspath('seizure.db')}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

# =======================
# TABLES
# =======================
users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

devices = sqlalchemy.Table(
    "devices", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("device_id", sqlalchemy.String, unique=True),
    sqlalchemy.Column("label", sqlalchemy.String),
    sqlalchemy.Column("last_seen", sqlalchemy.DateTime, nullable=True),
)

sensor_data = sqlalchemy.Table(
    "sensor_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, index=True),
    sqlalchemy.Column("mag_x", sqlalchemy.Integer),
    sqlalchemy.Column("mag_y", sqlalchemy.Integer),
    sqlalchemy.Column("mag_z", sqlalchemy.Integer),
    sqlalchemy.Column("battery_percent", sqlalchemy.Integer),
    sqlalchemy.Column("seizure_flag", sqlalchemy.Boolean, default=False),
)

seizure_events = sqlalchemy.Table(
    "seizure_events", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
    sqlalchemy.Column("device_ids", sqlalchemy.String),
)

metadata.create_all(engine)

# =======================
# AUTH
# =======================
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = now_pht() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_username(username: str):
    return await database.fetch_one(users.select().where(users.c.username == username))

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user or password != user["password"]:
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    exc = HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise exc
    except JWTError:
        raise exc
    user = await get_user_by_username(username)
    if not user:
        raise exc
    return user

# =======================
# APP INIT
# =======================
app = FastAPI(title="Seizure Monitor Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# =======================
# MODELS
# =======================
class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

class DeviceRegister(BaseModel):
    device_id: str
    label: Optional[str] = None

class DeviceUpdate(BaseModel):
    label: str

class UnifiedESP32Payload(BaseModel):
    device_id: str
    timestamp_ms: int
    battery_percent: int
    seizure_flag: bool
    mag_x: int
    mag_y: int
    mag_z: int

# =======================
# HELPERS
# =======================
async def log_device_connection(device_id: str, ts: datetime):
    await database.execute(
        devices.update().where(devices.c.device_id == device_id).values(last_seen=ts)
    )

def is_connected(last_seen: datetime, timeout: int = 60):
    if not last_seen:
        return False
    return (now_pht() - last_seen).total_seconds() <= timeout

# =======================
# ROUTES
# =======================
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "db": DATABASE_URL}

@app.post("/api/register")
async def register(u: UserCreate):
    if await get_user_by_username(u.username):
        raise HTTPException(status_code=400, detail="Username exists")
    user_id = await database.execute(users.insert().values(
        username=u.username,
        password=u.password,
        is_admin=u.is_admin
    ))
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid login")
    token = create_access_token(
        {"sub": user["username"], "is_admin": user["is_admin"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}

# -----------------------
# DEVICE MANAGEMENT
# -----------------------
@app.post("/api/devices/register")
async def register_device(d: DeviceRegister, current_user=Depends(get_current_user)):
    if await database.fetch_one(devices.select().where(devices.c.device_id == d.device_id)):
        raise HTTPException(status_code=400, detail="Device ID exists")
    await database.execute(devices.insert().values(
        user_id=current_user["id"],
        device_id=d.device_id,
        label=d.label or d.device_id
    ))
    return {"status": "ok", "device_id": d.device_id}

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, body: DeviceUpdate, current_user=Depends(get_current_user)):
    row = await database.fetch_one(devices.select().where(
        (devices.c.device_id == device_id) & (devices.c.user_id == current_user["id"])
    ))
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.update().where(devices.c.id == row["id"]).values(label=body.label))
    return {"status": "updated"}

# -----------------------
# DEVICE DATA UPLOAD
# -----------------------
@app.post("/api/device/upload")
async def upload_from_esp(payload: UnifiedESP32Payload):
    device = await database.fetch_one(devices.select().where(devices.c.device_id == payload.device_id))
    if not device:
        raise HTTPException(status_code=403, detail="Unknown device")

    ts = from_ms_to_pht(payload.timestamp_ms)

    # Save sensor data
    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts,
        mag_x=payload.mag_x,
        mag_y=payload.mag_y,
        mag_z=payload.mag_z,
        battery_percent=payload.battery_percent,
        seizure_flag=payload.seizure_flag
    ))

    # Update last_seen based on ESP32 timestamp
    await log_device_connection(payload.device_id, ts)

    # Seizure detection (window=5s, trigger if 3 devices report seizure)
    if payload.seizure_flag:
        user_id = device["user_id"]
        window_start = ts - timedelta(seconds=5)
        user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
        ids = [d["device_id"] for d in user_devices]

        recent_rows = await database.fetch_all(
            sensor_data.select()
            .where(sensor_data.c.device_id.in_(ids))
            .where(sensor_data.c.timestamp >= window_start)
        )

        triggered = list({r["device_id"] for r in recent_rows if r["seizure_flag"]})

        if len(triggered) >= 3:
            existing_event = await database.fetch_one(
                seizure_events.select()
                .where(seizure_events.c.user_id == user_id)
                .where(seizure_events.c.timestamp >= window_start)
            )
            if not existing_event:
                await database.execute(seizure_events.insert().values(
                    user_id=user_id,
                    timestamp=ts,
                    device_ids=",".join(triggered)
                ))

    return {"status": "saved"}

# -----------------------
# DEVICES + LATEST DATA
# -----------------------
@app.get("/api/mydevices_with_latest_data")
async def my_devices_with_latest(current_user=Depends(get_current_user)):
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
    output = []
    now = now_pht()
    for d in user_devices:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == d["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        last_sync = latest["timestamp"].isoformat() if latest else None
        battery = latest["battery_percent"] if latest else 100
        seizure_flag = latest["seizure_flag"] if latest else False
        connected = is_connected(d["last_seen"])
        output.append({
            "device_id": d["device_id"],
            "label": d["label"],
            "battery_percent": battery,
            "last_sync": last_sync,
            "last_seen": d["last_seen"].isoformat() if d["last_seen"] else None,
            "mag_x": latest["mag_x"] if latest else 0,
            "mag_y": latest["mag_y"] if latest else 0,
            "mag_z": latest["mag_z"] if latest else 0,
            "seizure_flag": seizure_flag,
            "connected": connected
        })
    return output

# -----------------------
# ROOT
# -----------------------
@app.get("/")
async def root():
    return {"message": "Backend running"}

# =======================
# RUN
# =======================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
