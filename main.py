# =====================================================================
# SEIZURE MONITOR BACKEND - FIXED VERSION
# FIX 1: MIN_JERK_DURATION_SECONDS = 10 (stops 72-jerk chaining)
# FIX 2: MIN_GTCS_DURATION_SECONDS = 10
# FIX 3: GTCS continuous >= 1 (was >= 2, was blocking GTCS)
# =====================================================================
from fastapi import FastAPI, Depends, HTTPException
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
from sqlalchemy import and_
from fastapi.responses import StreamingResponse
import csv
import io

PHT = timezone(timedelta(hours=8))

def to_pht(dt_utc: datetime) -> datetime:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT)

def ts_pht_iso(dt_utc: Optional[datetime]) -> Optional[str]:
    if dt_utc is None:
        return None
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT).strftime("%Y-%m-%dT%H:%M:%S")

def parse_esp32_timestamp(timestamp_ms: int) -> datetime:
    ts_val = float(timestamp_ms)
    if ts_val > 1e12:
        ts_val = ts_val / 1000.0
    if 946684800 <= ts_val <= 4102444800:
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)
    print(f"[WARNING] Invalid timestamp: {timestamp_ms} — using server time")
    return datetime.now(timezone.utc)

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
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

users = sqlalchemy.Table("users", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("password", sqlalchemy.String),
    sqlalchemy.Column("is_admin", sqlalchemy.Boolean, default=False),
)

devices = sqlalchemy.Table("devices", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
    sqlalchemy.Column("device_id", sqlalchemy.String, unique=True),
    sqlalchemy.Column("label", sqlalchemy.String),
)

device_data = sqlalchemy.Table("device_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("payload", sqlalchemy.Text),
)

sensor_data = sqlalchemy.Table("sensor_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("accel_x", sqlalchemy.Float),
    sqlalchemy.Column("accel_y", sqlalchemy.Float),
    sqlalchemy.Column("accel_z", sqlalchemy.Float),
    sqlalchemy.Column("gyro_x", sqlalchemy.Float),
    sqlalchemy.Column("gyro_y", sqlalchemy.Float),
    sqlalchemy.Column("gyro_z", sqlalchemy.Float),
    sqlalchemy.Column("battery_percent", sqlalchemy.Integer),
    sqlalchemy.Column("seizure_flag", sqlalchemy.Boolean, default=False),
)

device_seizure_sessions = sqlalchemy.Table("device_seizure_sessions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
)

user_seizure_sessions = sqlalchemy.Table("user_seizure_sessions", metadata,
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

# ===== FIX: Increased minimum durations =====
MIN_JERK_DURATION_SECONDS = 10   # was 3 — prevents 72-jerk chaining
MIN_GTCS_DURATION_SECONDS = 10   # was 5

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

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_username(username: str):
    return await database.fetch_one(users.select().where(users.c.username == username))

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user or user["password"] != password:
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    exc = HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise exc
    except JWTError:
        raise exc
    user = await get_user_by_username(username)
    if not user:
        raise exc
    return user

async def get_active_device_seizure(device_id: str):
    return await database.fetch_one(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.device_id == device_id)
        .where(device_seizure_sessions.c.end_time == None)
        .order_by(device_seizure_sessions.c.start_time.desc())
    )

async def get_active_user_seizure(user_id: int, seizure_type: str):
    return await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == seizure_type)
        .where(user_seizure_sessions.c.end_time == None)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )

async def count_recent_seizure_readings(device_id: str, time_window_seconds: int = 5) -> int:
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=time_window_seconds)
    rows = await database.fetch_all(
        sensor_data.select().where(
            (sensor_data.c.device_id == device_id) &
            (sensor_data.c.timestamp >= cutoff_time) &
            (sensor_data.c.seizure_flag == True)
        )
    )
    return len(rows)

async def get_recent_seizure_data(device_ids: list, time_window_seconds: int = 5):
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

app = FastAPI(title="Seizure Monitor Backend - FIXED")

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

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"message": "Backend running - FIXED"}

@app.post("/api/register")
async def register(u: UserCreate):
    if await get_user_by_username(u.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    user_id = await database.execute(
        users.insert().values(username=u.username, password=u.password, is_admin=u.is_admin)
    )
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(
        {"sub": user["username"], "is_admin": user["is_admin"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/me")
async def get_me(current_user=Depends(get_current_user)):
    return {"id": current_user["id"], "username": current_user["username"], "is_admin": current_user["is_admin"]}

@app.post("/api/devices/register")
async def register_device(d: DeviceRegister, current_user=Depends(get_current_user)):
    my_devices = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
    if len(my_devices) >= 3:
        raise HTTPException(status_code=400, detail="Max 3 devices allowed")
    if await database.fetch_one(devices.select().where(devices.c.device_id == d.device_id)):
        raise HTTPException(status_code=400, detail="Device ID already exists")
    await database.execute(devices.insert().values(
        user_id=current_user["id"], device_id=d.device_id, label=d.label or d.device_id
    ))
    return {"status": "ok", "device_id": d.device_id}

@app.get("/api/devices")
async def get_user_devices(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
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
        accel_x = accel_y = accel_z = gyro_x = gyro_y = gyro_z = 0.0
        seizure_flag = False
        if latest:
            connected = latest["timestamp"] >= cutoff_time
            battery = latest["battery_percent"]
            last_sync_display = to_pht(latest["timestamp"]).strftime("%I:%M %p")
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
            "accel_x": accel_x, "accel_y": accel_y, "accel_z": accel_z,
            "gyro_x": gyro_x, "gyro_y": gyro_y, "gyro_z": gyro_z,
            "seizure_flag": seizure_flag,
        })
    return result

@app.get("/api/mydevices_with_latest_data")
async def get_my_devices_with_latest(current_user=Depends(get_current_user)):
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
    output = []
    now = datetime.now(PHT)
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=CONNECTED_THRESHOLD_SECONDS)
    for d in user_devices:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == d["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        connected = False
        last_sync_val = None
        accel_x = accel_y = accel_z = gyro_x = gyro_y = gyro_z = 0.0
        battery = 0
        seizure_flag = False
        if latest:
            connected = latest["timestamp"] >= cutoff_time
            battery = latest["battery_percent"]
            seizure_flag = latest["seizure_flag"] or False
            accel_x = latest["accel_x"] or 0.0
            accel_y = latest["accel_y"] or 0.0
            accel_z = latest["accel_z"] or 0.0
            gyro_x = latest["gyro_x"] or 0.0
            gyro_y = latest["gyro_y"] or 0.0
            gyro_z = latest["gyro_z"] or 0.0
            ts_ph = to_pht(latest["timestamp"])
            diff = (now - ts_ph).total_seconds()
            last_sync_val = "Just now" if diff <= 10 else ts_ph.strftime("%I:%M %p")
        output.append({
            "device_id": d["device_id"],
            "label": d["label"],
            "battery_percent": battery,
            "last_sync": last_sync_val,
            "connected": connected,
            "accel_x": accel_x, "accel_y": accel_y, "accel_z": accel_z,
            "gyro_x": gyro_x, "gyro_y": gyro_y, "gyro_z": gyro_z,
            "seizure_flag": seizure_flag,
        })
    return output

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, update: DeviceUpdate, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select().where(devices.c.device_id == device_id).where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.update().where(devices.c.device_id == device_id).values(label=update.label))
    return {"message": "Device updated"}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select().where(devices.c.device_id == device_id).where(devices.c.user_id == current_user["id"])
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.delete().where(devices.c.device_id == device_id))
    return {"message": "Device deleted"}

@app.get("/api/seizure_events/latest")
async def get_latest_event(current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .where(user_seizure_sessions.c.end_time == None)
        .order_by(user_seizure_sessions.c.start_time.desc()).limit(1)
    )
    if not row:
        row = await database.fetch_one(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == current_user["id"])
            .order_by(user_seizure_sessions.c.start_time.desc()).limit(1)
        )
    if not row:
        return {}
    return {"type": row["type"], "start": ts_pht_iso(row["start_time"]), "end": ts_pht_iso(row["end_time"]) if row["end_time"] else None}

@app.get("/api/seizure_events/all")
async def get_all_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return [{"type": r["type"], "start": ts_pht_iso(r["start_time"]), "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None} for r in rows]

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
        duration = str((r["end_time"] - r["start_time"]).total_seconds()) if r["end_time"] else ""
        writer.writerow([r["type"], start, end, duration])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=seizure_events.csv"})

@app.get("/api/seizure_events")
async def get_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return [{"type": r["type"], "start": ts_pht_iso(r["start_time"]), "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None} for r in rows]

@app.get("/api/latest_seizure_event")
async def get_latest_seizure_event(current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc()).limit(1)
    )
    if not row:
        return None
    return {"type": row["type"], "start_time": ts_pht_iso(row["start_time"]), "end_time": ts_pht_iso(row["end_time"])}

# =====================================================================
# ESP32 UPLOAD - FIXED
# FIX: GTCS requires continuous >= 1 (was >= 2)
# =====================================================================
@app.post("/api/device/upload")
async def upload_device_data(payload: UnifiedESP32Payload):
    existing = await database.fetch_one(devices.select().where(devices.c.device_id == payload.device_id))
    if not existing:
        raise HTTPException(status_code=404, detail=f"Device {payload.device_id} not registered")

    ts_utc = parse_esp32_timestamp(payload.timestamp_ms)
    print(f"[UPLOAD] device={payload.device_id} | seizure={payload.seizure_flag} | ts={to_pht(ts_utc).strftime('%H:%M:%S PHT')}")

    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id, timestamp=ts_utc,
        accel_x=payload.accel_x, accel_y=payload.accel_y, accel_z=payload.accel_z,
        gyro_x=payload.gyro_x, gyro_y=payload.gyro_y, gyro_z=payload.gyro_z,
        battery_percent=payload.battery_percent, seizure_flag=payload.seizure_flag
    ))

    await database.execute(device_data.insert().values(
        device_id=payload.device_id, timestamp=ts_utc,
        payload=json.dumps({
            "accel_x": payload.accel_x, "accel_y": payload.accel_y, "accel_z": payload.accel_z,
            "gyro_x": payload.gyro_x, "gyro_y": payload.gyro_y, "gyro_z": payload.gyro_z,
            "battery_percent": payload.battery_percent, "seizure_flag": payload.seizure_flag,
        })
    ))

    active_device = await get_active_device_seizure(payload.device_id)
    if payload.seizure_flag:
        if not active_device:
            await database.execute(device_seizure_sessions.insert().values(
                device_id=payload.device_id, start_time=ts_utc, end_time=None
            ))
    else:
        if active_device:
            await database.execute(
                device_seizure_sessions.update()
                .where(device_seizure_sessions.c.id == active_device["id"])
                .values(end_time=ts_utc)
            )

    user_id = existing["user_id"]
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    device_ids = [d["device_id"] for d in user_devices]

    seizure_data = await get_recent_seizure_data(device_ids, time_window_seconds=4)
    devices_with_seizure = seizure_data['devices_with_seizure']
    device_seizure_counts = seizure_data['device_seizure_counts']

    print(f"[DETECTION] user={user_id} | devices_with_seizure={devices_with_seizure}/{len(device_ids)} | counts={device_seizure_counts}")

    # CASE 1: GTCS
    if devices_with_seizure >= 2:
        continuous = sum(1 for c in device_seizure_counts.values() if c >= 2)
        if continuous >= 1:  # FIX: was >= 2
            active_gtcs = await get_active_user_seizure(user_id, "GTCS")
            if not active_gtcs:
                print(f"[GTCS] *** STARTING GTCS for user {user_id} ***")
                await database.execute(user_seizure_sessions.insert().values(
                    user_id=user_id, type="GTCS", start_time=ts_utc, end_time=None
                ))
            active_jerk = await get_active_user_seizure(user_id, "Jerk")
            if active_jerk:
                jerk_duration = (ts_utc - active_jerk["start_time"]).total_seconds()
                if jerk_duration >= MIN_JERK_DURATION_SECONDS:
                    print(f"[JERK->GTCS] Closing Jerk (dur={jerk_duration:.1f}s)")
                    await database.execute(
                        user_seizure_sessions.update()
                        .where(user_seizure_sessions.c.id == active_jerk["id"])
                        .values(end_time=ts_utc)
                    )
            return {"status": "saved", "event": "GTCS"}

    # CASE 2: JERK
    active_gtcs = await get_active_user_seizure(user_id, "GTCS")
    if devices_with_seizure >= 1 and not active_gtcs:
        recent_gtcs = await database.fetch_one(
            user_seizure_sessions.select()
            .where(user_seizure_sessions.c.user_id == user_id)
            .where(user_seizure_sessions.c.type == "GTCS")
            .where(user_seizure_sessions.c.end_time != None)
            .order_by(user_seizure_sessions.c.end_time.desc()).limit(1)
        )
        if recent_gtcs and recent_gtcs["end_time"]:
            time_since_end = (ts_utc - recent_gtcs["end_time"]).total_seconds()
            if time_since_end < 30:
                print(f"[GTCS] Reopening (ended {time_since_end:.0f}s ago)")
                await database.execute(
                    user_seizure_sessions.update()
                    .where(user_seizure_sessions.c.id == recent_gtcs["id"])
                    .values(end_time=None)
                )
                return {"status": "saved", "event": "GTCS_reopened"}

        active_jerk = await get_active_user_seizure(user_id, "Jerk")
        if not active_jerk:
            print(f"[JERK] *** STARTING JERK for user {user_id} ***")
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id, type="Jerk", start_time=ts_utc, end_time=None
            ))
        else:
            print(f"[JERK] Already active (id={active_jerk['id']})")
        return {"status": "saved", "event": "Jerk"}

    # CASE 3: NO SEIZURE
    if devices_with_seizure == 0:
        active_gtcs = await get_active_user_seizure(user_id, "GTCS")
        if active_gtcs:
            gtcs_duration = (ts_utc - active_gtcs["start_time"]).total_seconds()
            if gtcs_duration >= MIN_GTCS_DURATION_SECONDS:
                print(f"[GTCS] Closing (dur={gtcs_duration:.1f}s)")
                await database.execute(
                    user_seizure_sessions.update()
                    .where(user_seizure_sessions.c.id == active_gtcs["id"])
                    .values(end_time=ts_utc)
                )
            else:
                print(f"[GTCS] Keeping open (dur={gtcs_duration:.1f}s < min {MIN_GTCS_DURATION_SECONDS}s)")

        active_jerk = await get_active_user_seizure(user_id, "Jerk")
        if active_jerk:
            jerk_duration = (ts_utc - active_jerk["start_time"]).total_seconds()
            if jerk_duration >= MIN_JERK_DURATION_SECONDS:
                print(f"[JERK] Closing (dur={jerk_duration:.1f}s)")
                await database.execute(
                    user_seizure_sessions.update()
                    .where(user_seizure_sessions.c.id == active_jerk["id"])
                    .values(end_time=ts_utc)
                )
            else:
                print(f"[JERK] Keeping open (dur={jerk_duration:.1f}s < min {MIN_JERK_DURATION_SECONDS}s)")

    return {"status": "saved", "event": "none"}

# =====================================================================
# ADMIN ROUTES
# =====================================================================
@app.get("/api/users")
async def get_all_users(current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(users.select())
    return [{"id": r["id"], "username": r["username"], "is_admin": r["is_admin"]} for r in rows]

@app.get("/api/admin/user/{user_id}/devices")
async def admin_get_user_devices(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    return await database.fetch_all(devices.select().where(devices.c.user_id == user_id))

@app.get("/api/admin/user/{user_id}/events")
async def admin_get_user_events(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    return [{"type": r["type"], "start": ts_pht_iso(r["start_time"]), "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None} for r in rows]

@app.get("/api/admin/user/{user_id}/events/{start}/data")
async def get_event_sensor_data(user_id: int, start: str, end: Optional[str] = None, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    start_dt_utc = datetime.fromisoformat(start).replace(tzinfo=PHT).astimezone(timezone.utc)
    end_dt_utc = datetime.fromisoformat(end).replace(tzinfo=PHT).astimezone(timezone.utc) if end else None

    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    device_ids = [d["device_id"] for d in user_devices]

    query = sensor_data.select().where(
        and_(sensor_data.c.device_id.in_(device_ids), sensor_data.c.timestamp >= start_dt_utc)
    )
    if end_dt_utc:
        query = query.where(sensor_data.c.timestamp <= end_dt_utc)

    rows = await database.fetch_all(query.order_by(sensor_data.c.timestamp.asc()))
    return [
        {
            "timestamp": ts_pht_iso(r["timestamp"]),
            "device_id": r["device_id"],
            "accel_x": r["accel_x"], "accel_y": r["accel_y"], "accel_z": r["accel_z"],
            "gyro_x": r["gyro_x"], "gyro_y": r["gyro_y"], "gyro_z": r["gyro_z"],
            "battery_percent": r["battery_percent"],
            "seizure_flag": r["seizure_flag"],
        }
        for r in rows
    ]

@app.delete("/api/delete_user/{user_id}")
async def delete_user(user_id: int, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    user = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await database.execute(devices.delete().where(devices.c.user_id == user_id))
    await database.execute(users.delete().where(users.c.id == user_id))
    return {"detail": f"User {user['username']} deleted"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)