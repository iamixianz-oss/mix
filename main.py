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

PHT = timezone(timedelta(hours=8))
def format_pht_human(dt_utc: datetime) -> Optional[str]:
    if not dt_utc:
        return None
    dt = to_pht(dt_utc)
    return dt.strftime("%-m/%-d/%Y at %-I:%M %p")

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
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

app = FastAPI(title="Seizure Monitor Backend")

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

device_seizure_sessions = sqlalchemy.Table(
    "device_seizure_sessions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("device_id", sqlalchemy.String, index=True),
    sqlalchemy.Column("start_time", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("end_time", sqlalchemy.DateTime(timezone=True), nullable=True),
)

user_seizure_sessions = sqlalchemy.Table(
    "user_seizure_sessions", metadata,
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

#HELPER FUNCTIONS
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

async def get_active_device_seizure(device_id: str):
    return await database.fetch_one(
        device_seizure_sessions.select()
        .where(device_seizure_sessions.c.device_id == device_id)
        .where(device_seizure_sessions.c.end_time == None)
    )

async def get_active_user_seizure(user_id: int, seizure_type: str):
    return await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == user_id)
        .where(user_seizure_sessions.c.type == seizure_type)
        .where(user_seizure_sessions.c.end_time == None)
    )

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
    metadata.create_all(engine)
    asyncio.create_task(log_device_status_changes())

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "db": DATABASE_URL}

#DEVICE CONNECTION LOGGING
device_states = {}
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
                connected = diff <= 10

            last_state = device_states.get(d["device_id"])
            if last_state != connected:
                status = "CONNECTED" if connected else "DISCONNECTED"
                print(f"[{now.isoformat()}] Device {d['device_id']} (Owner: {username}) is {status}")
                device_states[d["device_id"]] = connected

        await asyncio.sleep(1)



# ADMIN ROUTES
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


@app.get("/api/admin/user/{user_id}/events/{start}/data")
async def get_event_sensor_data(user_id: int, start: str, current_user=Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    
    start_dt = datetime.fromisoformat(start)
    rows = await database.fetch_all(
        sensor_data.select()
        .where(sensor_data.c.device_id.in_(
            [d["device_id"] for d in await database.fetch_all(devices.select().where(devices.c.user_id==user_id))]
        ))
        .where(sensor_data.c.timestamp >= start_dt)
        .order_by(sensor_data.c.timestamp.asc())
    )
    
    result = []
    for r in rows:
        result.append({
            "timestamp": ts_pht_iso(r["timestamp"]),
            "mag_x": r["mag_x"],
            "mag_y": r["mag_y"],
            "mag_z": r["mag_z"],
            "battery_percent": r["battery_percent"],
            "seizure_flag": r["seizure_flag"],
        })
    return result

# SEIZURE EVENTS
@app.get("/api/seizure_events")
async def get_seizure_events(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
    )
    result = []
    for r in rows:
        start = ts_pht_iso(r["start_time"])
        end = ts_pht_iso(r["end_time"]) if r["end_time"] else None
        result.append({
            "type": r["type"],
            "start": start,
            "end": end
        })
    return result

@app.get("/api/seizure_events/latest")
async def get_latest_event(current_user=Depends(get_current_user)):
    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .order_by(user_seizure_sessions.c.start_time.desc())
        .limit(1)
    )
    if rows:
        r = rows[0]
        return {
            "type": r["type"],
            "start": ts_pht_iso(r["start_time"]),
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None
        }
    return {}

@app.get("/api/seizure_events/all")
async def get_all_seizure_events(current_user=Depends(get_current_user)):
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
            "end": ts_pht_iso(r["end_time"]) if r["end_time"] else None
        })
    return result

#USER ROUTES
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
    
@app.get("/api/seizures/gtcs/today")
async def get_gtcs_today(current_user=Depends(get_current_user)):
    now = datetime.now(PHT)
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

    rows = await database.fetch_all(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .where(user_seizure_sessions.c.type == "GTCS")
        .where(user_seizure_sessions.c.start_time >= start_of_day)
    )

    return {"gtcs_today": len(rows)}

@app.get("/api/seizures/gtcs/last")
async def get_last_gtcs(current_user=Depends(get_current_user)):
    row = await database.fetch_one(
        user_seizure_sessions.select()
        .where(user_seizure_sessions.c.user_id == current_user["id"])
        .where(user_seizure_sessions.c.type == "GTCS")
        .order_by(user_seizure_sessions.c.start_time.desc())
        .limit(1)
    )

    if not row:
        return {"last_gtcs": None}

    return {
        "type": "GTCS",
        "start": ts_pht_iso(row["start_time"]),
        "end": ts_pht_iso(row["end_time"]) if row["end_time"] else None
    }

# DEVICE ROUTES
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

#DEVICE HISTORY
def ts_pht_iso(dt_utc: datetime) -> str:
    return to_pht(dt_utc).isoformat()
def ts_pht_human(dt_utc: datetime) -> str:
    """Return PH time formatted like 'MM/DD/YYYY HH:MM AM/PM'"""
    dt = to_pht(dt_utc)
    return dt.strftime("%m/%d/%Y %I:%M %p")

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
        result.append({
            "id": row["id"],
            "device_id": row["device_id"],
            "timestamp": ts_pht_human(row["timestamp"]),  # <-- human readable PH time
            "mag_x": payload.get("mag_x"),
            "mag_y": payload.get("mag_y"),
            "mag_z": payload.get("mag_z"),
            "battery_percent": payload.get("battery_percent", 100),
            "seizure_flag": payload.get("seizure_flag", False)
        })

    return result



#DEVICE UPLOAD
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

    await database.execute(device_data.insert().values(
        device_id=payload.device_id,
        timestamp=ts_utc,
        payload=json.dumps(payload.dict())
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
    user_devices = await database.fetch_all(devices.select().where(devices.c.user_id == user_id))
    device_ids = [d["device_id"] for d in user_devices]

    time_window = ts_utc - timedelta(seconds=3)

    triggered_count = 0
    for did in device_ids:
        rows = await database.fetch_all(
            sensor_data.select()
            .where(sensor_data.c.device_id == did)
            .where(sensor_data.c.timestamp >= time_window)
        )

        if any(r["seizure_flag"] for r in rows):
            triggered_count += 1

    if triggered_count >= 3:
        active_session = await get_active_user_seizure(user_id, "GTCS")
        if not active_session:
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
    elif triggered_count >= 1:
        active_session = await get_active_user_seizure(user_id, "Jerk")
        if not active_session:
            await database.execute(user_seizure_sessions.insert().values(
                user_id=user_id,
                type="Jerk",
                start_time=ts_utc,
                end_time=None
            ))
        gtcs_session = await get_active_user_seizure(user_id, "GTCS")
        if gtcs_session:
            await database.execute(user_seizure_sessions.update()
                                   .where(user_seizure_sessions.c.id == gtcs_session["id"])
                                   .values(end_time=ts_utc))
    else:
        for stype in ["GTCS", "Jerk"]:
            session = await get_active_user_seizure(user_id, stype)
            if session:
                await database.execute(user_seizure_sessions.update()
                                       .where(user_seizure_sessions.c.id == session["id"])
                                       .values(end_time=ts_utc))

    return {"status": "saved"}


# LATEST SENSOR DATA
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



@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"message": "Backend running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
