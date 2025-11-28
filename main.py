from fastapi import FastAPI, Depends, HTTPException, Body
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

# =======================
#   PH TIMEZONE
# =======================
PHT = timezone(timedelta(hours=8))

def to_pht(dt_utc: datetime) -> datetime:
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    return dt_utc.astimezone(PHT)

# =======================
#   DATABASE CONFIG
# =======================
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

app = FastAPI(title="Seizure Monitor Backend")

# =======================
#   TABLE DEFINITIONS
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
)

device_data = sqlalchemy.Table(
    "device_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("payload", sqlalchemy.Text),
)

sensor_data = sqlalchemy.Table(
    "sensor_data", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
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
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("device_ids", sqlalchemy.String),
)

metadata.create_all(engine)

# =======================
#   AUTH
# =======================
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

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
#   HELPER FUNCTIONS
# =======================
async def get_user_by_username(username: str):
    return await database.fetch_one(users.select().where(users.c.username == username))

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user or user["password"] != password:
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(PHT) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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
#   CORS
# =======================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =======================
#   DEVICE CONNECTION LOGGING
# =======================
device_states = {}  # device_id -> connected

async def log_device_status_changes():
    while True:
        now = datetime.now(PHT)
        all_devices = await database.fetch_all(devices.select())
        for d in all_devices:
            user_row = await database.fetch_one(users.select().where(users.c.id == d["user_id"]))
            username = user_row["username"] if user_row else "Unknown"

            latest = await database.fetch_one(
                sensor_data.select()
                .where(sensor_data.c.device_id == d["device_id"])
                .order_by(sensor_data.c.timestamp.desc())
                .limit(1)
            )

            connected = False
            if latest:
                ts = to_pht(latest["timestamp"])
                diff = (now - ts).total_seconds()
                connected = diff <= 5  # 5 seconds for connected

            last_state = device_states.get(d["device_id"])
            if last_state != connected:
                status = "CONNECTED" if connected else "DISCONNECTED"
                print(f"[{now.isoformat()}] Device {d['device_id']} (Owner: {username}) is {status}")
                device_states[d["device_id"]] = connected

        await asyncio.sleep(1)

# =======================
#   LIFECYCLE
# =======================
@app.on_event("startup")
async def startup():
    await database.connect()
    asyncio.create_task(log_device_status_changes())

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "db": DATABASE_URL}

# =======================
#   USER ROUTES
# =======================
@app.post("/api/register")
async def register(u: UserCreate):
    if await get_user_by_username(u.username):
        raise HTTPException(status_code=400, detail="Username exists")
    query = users.insert().values(username=u.username, password=u.password, is_admin=u.is_admin)
    user_id = await database.execute(query)
    return {"id": user_id, "username": u.username}

@app.post("/api/login", response_model=Token)
async def login(body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid login")
    token = create_access_token(
        {"sub": user["username"], "is_admin": user["is_admin"]},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/me")
async def get_me(current_user=Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "is_admin": current_user["is_admin"],
    }

# =======================
#   DEVICE ROUTES
# =======================
@app.post("/api/devices/register")
async def register_device(d: DeviceRegister, current_user=Depends(get_current_user)):
    my_devices = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
    if len(my_devices) >= 4:
        raise HTTPException(status_code=400, detail="Max 4 devices allowed")
    if await database.fetch_one(devices.select().where(devices.c.device_id == d.device_id)):
        raise HTTPException(status_code=400, detail="Device ID exists")
    await database.execute(
        devices.insert().values(user_id=current_user["id"], device_id=d.device_id, label=d.label or d.device_id)
    )
    return {"status": "ok", "device_id": d.device_id}

@app.get("/api/mydevices")
async def get_my_devices(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(devices.select().where(devices.c.user_id == current_user["id"]))
    output = []
    for r in rows:
        latest_data = await database.fetch_one(
            device_data.select()
            .where(device_data.c.device_id == r["device_id"])
            .order_by(device_data.c.timestamp.desc())
            .limit(1)
        )
        battery = 100
        last_sync_val = None
        if latest_data:
            payload = json.loads(latest_data["payload"])
            battery = payload.get("battery_percent", 100)
            ts = to_pht(latest_data["timestamp"])
            now = datetime.now(PHT)
            diff = (now - ts).total_seconds()
            last_sync_val = "Just now" if diff <= 10 else ts.isoformat()
        output.append({
            "device_id": r["device_id"],
            "label": r["label"],
            "battery_percent": battery,
            "last_sync": last_sync_val
        })
    return output

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, body: DeviceUpdate, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select().where(
            (devices.c.device_id == device_id) &
            (devices.c.user_id == current_user["id"])
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.update().where(devices.c.id == row["id"]).values(label=body.label))
    return {"status": "updated", "device_id": device_id, "label": body.label}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str, current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        devices.select().where(
            (devices.c.device_id == device_id) &
            (devices.c.user_id == current_user["id"])
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    await database.execute(devices.delete().where(devices.c.id == row["id"]))
    return {"status": "deleted", "device_id": device_id}

# =======================
#   DEVICE HISTORY
# =======================
@app.get("/api/devices/{device_id}", response_model=List[dict])
async def get_device_history(device_id: str, current_user=Depends(get_current_user)):
    r = await database.fetch_one(
        devices.select().where(
            (devices.c.device_id == device_id) &
            (devices.c.user_id == current_user["id"])
        )
    )
    if not r:
        raise HTTPException(status_code=403, detail="Not your device")
    
    rows = await database.fetch_all(
        device_data.select()
        .where(device_data.c.device_id == device_id)
        .order_by(device_data.c.timestamp.desc())
        .limit(1000)
    )

    result = []
    for row in rows:
        payload = json.loads(row["payload"])
        ts = to_pht(row["timestamp"])
        result.append({
            "id": row["id"],
            "device_id": row["device_id"],
            "timestamp": ts.strftime("%I:%M %p"),
            "payload": payload,
            "battery_percent": payload.get("battery_percent", 100),
        })
    return result


# =======================
#   SEIZURE EVENTS
# =======================
@app.get("/api/seizure_events")
async def get_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        seizure_events.select()
        .where(seizure_events.c.user_id == current_user["id"])
        .order_by(seizure_events.c.timestamp.desc())
    )
    return [{
        "timestamp": to_pht(r["timestamp"]).strftime("%I:%M %p"),
        "device_ids": r["device_ids"].split(",")
    } for r in rows]


@app.get("/api/seizure_events/latest")
async def get_latest_event(current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        seizure_events.select()
        .where(seizure_events.c.user_id == current_user["id"])
        .order_by(seizure_events.c.timestamp.desc())
        .limit(1)
    )
    if not row:
        return {}
    return {
        "timestamp": to_pht(row["timestamp"]).strftime("%I:%M %p"),
        "device_ids": row["device_ids"].split(",")
    }


@app.get("/api/seizure_events/all")
async def get_all_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        seizure_events.select().order_by(seizure_events.c.timestamp.desc())
    )
    return [{
        "timestamp": to_pht(r["timestamp"]).strftime("%I:%M %p"),
        "device_ids": r["device_ids"].split(",")
    } for r in rows]

# =======================
#   ESP32 UPLOAD
# =======================
@app.post("/api/device/upload")
async def upload_from_esp(payload: UnifiedESP32Payload):
    existing = await database.fetch_one(
        devices.select().where(devices.c.device_id == payload.device_id)
    )
    if not existing:
        raise HTTPException(status_code=403, detail="Unknown device_id")

    ts_val = payload.timestamp_ms
    if ts_val > 1e12:  
        ts_val = ts_val / 1000.0

    ts_utc = datetime.utcfromtimestamp(ts_val).replace(tzinfo=timezone.utc)

    await database.execute(sensor_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        mag_x=payload.mag_x,
        mag_y=payload.mag_y,
        mag_z=payload.mag_z,
        battery_percent=payload.battery_percent,
        seizure_flag=payload.seizure_flag
    ))

    raw_json = {
        "device_id": payload.device_id,
        "timestamp_ms": payload.timestamp_ms,
        "battery_percent": payload.battery_percent,
        "seizure_flag": payload.seizure_flag,
        "mag_x": payload.mag_x,
        "mag_y": payload.mag_y,
        "mag_z": payload.mag_z
    }

    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        payload=json.dumps(raw_json)
    ))

    if payload.seizure_flag:
        user_id = existing["user_id"]
        window_start = ts_utc - timedelta(seconds=5)

        user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
        ids = [d["device_id"] for d in user_devices]

        recent_rows = await database.fetch_all(
            device_data.select()
            .where(device_data.c.device_id.in_(ids))
            .where(device_data.c.timestamp >= window_start)
        )

        triggered = list({
            r["device_id"]
            for r in recent_rows
            if json.loads(r["payload"]).get("seizure_flag")
        })

        if len(triggered) >= 3:
            recent_log = await database.fetch_one(
                seizure_events.select()
                .where(seizure_events.c.user_id == user_id)
                .where(seizure_events.c.timestamp >= window_start)
            )
            if not recent_log:
                await database.execute(seizure_events.insert().values(
                    user_id=user_id,
                    timestamp=ts_utc,
                    device_ids=",".join(triggered)
                ))

    return {"status": "saved"}

# =======================
#   DEVICES + LATEST SENSOR DATA
# =======================
@app.get("/api/mydevices_with_latest_data")
async def get_my_devices_with_latest(current_user=Depends(get_current_user)):
    user_devices = await database.fetch_all(
        devices.select().where(devices.c.user_id == current_user["id"])
    )
    output = []
    now = datetime.now(PHT)
    for d in user_devices:
        latest = await database.fetch_one(
            sensor_data.select()
            .where(sensor_data.c.device_id == d["device_id"])
            .order_by(sensor_data.c.timestamp.desc())
            .limit(1)
        )
        if latest:
            ts_ph = to_pht(latest["timestamp"])
            diff = (now - ts_ph).total_seconds()
            last_sync_val = "Just now" if diff <= 10 else ts_ph.strftime("%I:%M %p")
            connected = diff <= 10
        else:
            last_sync_val = None
            connected = False

        output.append({
            "device_id": d["device_id"],
            "label": d["label"],
            "battery_percent": latest["battery_percent"] if latest else 100,
            "last_sync": last_sync_val,
            "mag_x": latest["mag_x"] if latest else 0,
            "mag_y": latest["mag_y"] if latest else 0,
            "mag_z": latest["mag_z"] if latest else 0,
            "seizure_flag": latest["seizure_flag"] if latest else False,
            "connected": connected
        })
    return output


# =======================
#   ROOT
# =======================
@app.get("/")
async def root():
    return {"message": "Backend running"}

# =======================
#   RUN
# =======================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
