from fastapi import FastAPI, Depends, HTTPException, Body, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import databases
import sqlalchemy
from fastapi.security import OAuth2PasswordBearer
import os
import json
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from sqlalchemy import and_
from fastapi.responses import StreamingResponse
import csv
import io
import math

PHT = timezone(timedelta(hours=8))

def to_pht(dt_utc: datetime) -> datetime:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT)

if "DATABASE_URL" in os.environ:
    raw_url = os.environ["DATABASE_URL"]
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)
    DATABASE_URL = raw_url
else:
    DATABASE_URL = f"sqlite:///{os.path.abspath('seizure.db')}"

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

app = FastAPI(title="Seizure Monitor Backend - MPU6050")

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

devices = sqlalchemy.Table(
    "devices",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("device_id", sqlalchemy.String, unique=True),
    sqlalchemy.Column("label", sqlalchemy.String),
)

device_data = sqlalchemy.Table(
    "device_data",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("payload", sqlalchemy.Text),
)

# MPU6050 sensor data - accelerometer and gyroscope only
sensor_data = sqlalchemy.Table(
    "sensor_data",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    # Accelerometer values (MPU6050)
    sqlalchemy.Column("accel_x", sqlalchemy.Float),
    sqlalchemy.Column("accel_y", sqlalchemy.Float),
    sqlalchemy.Column("accel_z", sqlalchemy.Float),
    # Gyroscope values (MPU6050)
    sqlalchemy.Column("gyro_x", sqlalchemy.Float),
    sqlalchemy.Column("gyro_y", sqlalchemy.Float),
    sqlalchemy.Column("gyro_z", sqlalchemy.Float),
    sqlalchemy.Column("battery_percent", sqlalchemy.Integer),
    sqlalchemy.Column("seizure_flag", sqlalchemy.Boolean, default=False),
)

seizure_events = sqlalchemy.Table(
    "seizure_events",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("device_ids", sqlalchemy.String),
)

device_seizure_sessions = sqlalchemy.Table(
    "device_seizure_sessions",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
)

user_seizure_sessions = sqlalchemy.Table(
    "user_seizure_sessions",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("type", sqlalchemy.String),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
)

metadata.create_all(engine)

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

CONNECTED_THRESHOLD_SECONDS = 30

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
    accel_x: float
    accel_y: float
    accel_z: float
    gyro_x: float
    gyro_y: float
    gyro_z: float

def parse_esp32_timestamp(timestamp_ms: int) -> datetime:
    """
    Safely parse ESP32 timestamp to timezone-aware UTC datetime.
    """
    ts_val = float(timestamp_ms)
    
    # Milliseconds → convert to seconds
    if ts_val > 1e12:
        ts_val = ts_val / 1000.0
    
    # Valid Unix timestamp range (year 2000 to 2100)
    if 946684800 <= ts_val <= 4102444800:
        ts_utc = datetime.fromtimestamp(ts_val, tz=timezone.utc)
    else:
        print(f"[WARNING] Invalid timestamp from ESP32: {timestamp_ms} — using server time")
        ts_utc = datetime.now(timezone.utc)
    
    return ts_utc

async def count_recent_seizure_readings(device_id: str, time_window_seconds: int = 5) -> int:
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=time_window_seconds)
    rows = await database.fetch_all(
        sensor_data.select()
        .where(
            (sensor_data.c.device_id == device_id) &
            (sensor_data.c.timestamp >= cutoff_time) &
            (sensor_data.c.seizure_flag == True)
        )
    )
    return len(rows)

async def get_recent_seizure_data(device_ids: list, time_window_seconds: int = 5):
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=time_window_seconds)
    
    devices_with_seizure = 0
    device_seizure_counts = {}
    
    for device_id in device_ids:
        count = await count_recent_seizure_readings(device_id, time_window_seconds)
        device_seizure_counts[device_id] = count
        if count > 0:
            devices_with_seizure += 1
    
    return {
        'devices_with_seizure': devices_with_seizure,
        'device_seizure_counts': device_seizure_counts
    }

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        row = await database.fetch_one(users.select().where(users.c.id == user_id))
        if row is None:
            raise HTTPException(status_code=401, detail="User not found")
        return dict(row)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def ts_pht_iso(ts_utc: Optional[datetime]) -> Optional[str]:
    if ts_utc is None:
        return None
    dt_pht = to_pht(ts_utc)
    return dt_pht.isoformat()

async def get_active_device_seizure(device_id: str):
    row = await database.fetch_one(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.device_id == device_id)
        .where(device_seizure_sessions.c.end_time == None)
        .order_by(device_seizure_sessions.c.start_time.desc())
    )
    return row

async def get_active_user_seizure(user_id: int, seizure_type: str):
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == seizure_type)
        .where(user_seizure_sessions.c.end_time == None)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return row

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/register")
async def register(user: UserCreate):
    existing = await database.fetch_one(
        users.select().where(users.c.username == user.username)
    )
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    await database.execute(
        users.insert().values(
            username=user.username,
            password=user.password,
            is_admin=user.is_admin
        )
    )
    return {"message": "User created"}

@app.post("/api/login", response_model=Token)
async def login(req: LoginRequest):
    row = await database.fetch_one(
        users.select().where(users.c.username == req.username)
    )
    if not row or row["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"user_id": row["id"]})
    return Token(access_token=token, token_type="bearer")

@app.get("/api/me")
async def get_me(current_user=Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "is_admin": current_user["is_admin"],
    }

@app.post("/api/devices")
async def register_device(device: DeviceRegister, current_user=Depends(get_current_user)):
    existing = await database.fetch_one(
        devices.select().where(devices.c.device_id == device.device_id)
    )
    if existing:
        raise HTTPException(status_code=400, detail="Device already registered")
    await database.execute(
        devices.insert().values(
            user_id=current_user["id"],
            device_id=device.device_id,
            label=device.label or device.device_id,
        )
    )
    return {"message": "Device registered"}

@app.get("/api/devices")
async def get_user_devices(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    result = []
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=CONNECTED_THRESHOLD_SECONDS)
    
    for row in rows:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == row["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        
        connected = False
        battery = 0
        last_sync_display = None
        accel_x = 0.0
        accel_y = 0.0
        accel_z = 0.0
        gyro_x = 0.0
        gyro_y = 0.0
        gyro_z = 0.0
        seizure_flag = False
        
        if latest:
            connected = latest["timestamp"] >= cutoff_time
            battery = latest["battery_percent"]
            dt_pht = to_pht(latest["timestamp"])
            last_sync_display = dt_pht.strftime("%I:%M %p")
            accel_x = latest["accel_x"] or 0.0
            accel_y = latest["accel_y"] or 0.0
            accel_z = latest["accel_z"] or 0.0
            gyro_x = latest["gyro_x"] or 0.0
            gyro_y = latest["gyro_y"] or 0.0
            gyro_z = latest["gyro_z"] or 0.0
            seizure_flag = latest["seizure_flag"] or False
        
        result.append({
            "id": row["id"],
            "device_id": row["device_id"],
            "label": row["label"],
            "connected": connected,
            "battery_percent": battery,
            "last_sync_display": last_sync_display,
            "accel_x": accel_x,
            "accel_y": accel_y,
            "accel_z": accel_z,
            "gyro_x": gyro_x,
            "gyro_y": gyro_y,
            "gyro_z": gyro_z,
            "seizure_flag": seizure_flag,
        })
    
    return result

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, update: DeviceUpdate, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select()
        .where(devices.c.device_id == device_id)
        .where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(
        devices.update()
        .where(devices.c.device_id == device_id)
        .values(label=update.label)
    )
    return {"message": "Device updated"}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select()
        .where(devices.c.device_id == device_id)
        .where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(
        devices.delete().where(devices.c.device_id == device_id)
    )
    return {"message": "Device deleted"}

@app.get("/api/latest_seizure_event")
async def get_latest_seizure_event(current_user=Depends(get_current_user)):
    user_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    device_ids = [d["device_id"] for d in user_devices]
    
    if not device_ids:
        return None
    
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
        .limit(1)
    )
    
    if not row:
        return None
    
    return {
        "type": row["type"],
        "start_time": ts_pht_iso(row["start_time"]),
        "end_time": ts_pht_iso(row["end_time"]),
    }

@app.get("/api/seizure_events")
async def get_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    
    result = []
    for r in rows:
        result.append({
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]),
        })
    
    return result

@app.get("/api/seizure_events/download")
async def download_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Start Time", "End Time", "Duration (seconds)"])
    
    for r in rows:
        start = ts_pht_iso(r["start_time"])
        end = ts_pht_iso(r["end_time"]) if r["end_time"] else "Ongoing"
        
        duration = ""
        if r["end_time"]:
            delta = r["end_time"] - r["start_time"]
            duration = str(delta.total_seconds())
        
        writer.writerow([r["type"], start, end, duration])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=seizure_events.csv"}
    )

@app.post("/api/device/upload")
async def upload_device_data(payload: UnifiedESP32Payload):
    existing = await database.fetch_one(
        devices.select().where(devices.c.device_id == payload.device_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device {payload.device_id} not registered")

    ts_utc = parse_esp32_timestamp(payload.timestamp_ms)

    # Store MPU6050 sensor data directly
    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        accel_x=payload.accel_x,
        accel_y=payload.accel_y,
        accel_z=payload.accel_z,
        gyro_x=payload.gyro_x,
        gyro_y=payload.gyro_y,
        gyro_z=payload.gyro_z,
        battery_percent=payload.battery_percent,
        seizure_flag=payload.seizure_flag
    ))

    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        payload=json.dumps({
            "accel_x": payload.accel_x,
            "accel_y": payload.accel_y,
            "accel_z": payload.accel_z,
            "gyro_x": payload.gyro_x,
            "gyro_y": payload.gyro_y,
            "gyro_z": payload.gyro_z,
            "battery_percent": payload.battery_percent,
            "seizure_flag": payload.seizure_flag,
        })
    ))

    active_device = await get_active_device_seizure(payload.device_id)
    if payload.seizure_flag:
        if not active_device:
            await database.execute(
                device_seizure_sessions.insert().values(
                    device_id=payload.device_id,
                    start_time=ts_utc,
                    end_time=None
                )
            )
    else:
        if active_device:
            await database.execute(
                device_seizure_sessions.update()
                .where(device_seizure_sessions.c.id == active_device["id"])
                .values(end_time=ts_utc)
            )

    user_id = existing["user_id"]
    user_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == user_id)
    )
    device_ids = [d["device_id"] for d in user_devices]

    seizure_data = await get_recent_seizure_data(device_ids, time_window_seconds=5)
    
    devices_with_seizure = seizure_data['devices_with_seizure']
    device_seizure_counts = seizure_data['device_seizure_counts']

    if devices_with_seizure >= 3:
        continuous_seizure_devices = sum(
            1 for count in device_seizure_counts.values() if count >= 2
        )
        
        if continuous_seizure_devices >= 2:
            active_gtcs = await get_active_user_seizure(user_id, "GTCS")
            if not active_gtcs:
                await database.execute(user_seizure_sessions.insert().values(
                    user_id=user_id,
                    type="GTCS",
                    start_time=ts_utc,
                    end_time=None
                ))
            
            jerk_session = await get_active_user_seizure(user_id, "Jerk")
            if jerk_session:
                await database.execute(user_seizure_sessions.update()
                    .where(user_seizure_sessions.c.id == jerk_session["id"])
                    .values(end_time=ts_utc))
            
            return {"status": "saved"}

    active_gtcs = await get_active_user_seizure(user_id, "GTCS")
    if not active_gtcs and devices_with_seizure >= 1:
        recent_gtcs = await database.fetch_one(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == user_id)
            .where(user_seizure_sessions.c.type == "GTCS")
            .where(user_seizure_sessions.c.end_time != None)
            .order_by(user_seizure_sessions.c.end_time.desc())
            .limit(1)
        )
        
        if recent_gtcs and recent_gtcs["end_time"]:
            time_since_gtcs_end = (ts_utc - recent_gtcs["end_time"]).total_seconds()
            if time_since_gtcs_end < 30:
                await database.execute(
                    user_seizure_sessions.update()
                    .where(user_seizure_sessions.c.id == recent_gtcs["id"])
                    .values(end_time=None)
                )
                return {"status": "saved"}
        
        active_jerk = await get_active_user_seizure(user_id, "Jerk")
        if not active_jerk:
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id,
                type="Jerk",
                start_time=ts_utc,
                end_time=None
            ))
        
        return {"status": "saved"}

    for stype in ["GTCS", "Jerk"]:
        session = await get_active_user_seizure(user_id, stype)
        if session:
            await database.execute(user_seizure_sessions.update()
                .where(user_seizure_sessions.c.id == session["id"])
                .values(end_time=ts_utc))

    return {"status": "saved"}

@app.get("/api/users")
async def get_all_users(current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(users.select())
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "username": r["username"],
            "is_admin": r["is_admin"],
        })
    return result

@app.get("/api/admin/user/{user_id}/devices")
async def admin_get_user_devices(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(
        devices.select().where(devices.c.user_id == user_id)
    )
    return rows

@app.get("/api/admin/user/{user_id}/events")
async def admin_get_user_events(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    result = []
    for r in rows:
        result.append({
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None
        })
    return result

@app.get("/api/admin/user/{user_id}/events/{start}/data")
async def get_event_sensor_data(user_id: int, start: str, end: Optional[str] = None, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    start_dt_naive = datetime.fromisoformat(start)
    start_dt_utc = start_dt_naive.replace(tzinfo=PHT).astimezone(timezone.utc)
    end_dt_utc = None
    if end:
        end_dt_naive = datetime.fromisoformat(end)
        end_dt_utc = end_dt_naive.replace(tzinfo=PHT).astimezone(timezone.utc)

    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    device_ids = [d["device_id"] for d in user_devices]
    query = sensor_data.select().where(
        and_(
            sensor_data.c.device_id.in_(device_ids),
            sensor_data.c.timestamp >= start_dt_utc,
        )
    )
    if end_dt_utc:
        query = query.where(sensor_data.c.timestamp <= end_dt_utc)
    rows = await database.fetch_all(query.order_by(sensor_data.c.timestamp.asc()))
    result = []
    for r in rows:
        result.append({
            "timestamp": ts_pht_iso(r["timestamp"]),
            "accel_x": r["accel_x"],
            "accel_y": r["accel_y"],
            "accel_z": r["accel_z"],
            "gyro_x": r["gyro_x"],
            "gyro_y": r["gyro_y"],
            "gyro_z": r["gyro_z"],
            "battery_percent": r["battery_percent"],
            "seizure_flag": r["seizure_flag"],
        })
    return result

@app.delete("/api/delete_user/{user_id}")
async def delete_user(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    user = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    delete_devices_query = devices.delete().where(devices.c.user_id == user_id)
    await database.execute(delete_devices_query)
    delete_user_query = users.delete().where(users.c.id == user_id)
    await database.execute(delete_user_query)
    return {"detail": f"User {user['username']} deleted successfully"}

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"message": "Backend running - MPU6050 Sensor"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
