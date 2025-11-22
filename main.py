import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
import jwt
from passlib.context import CryptContext

from database import db

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

app = FastAPI(title="HMS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return v
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        user["_id"] = str(user["_id"])
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


def require_roles(*roles):
    def checker(user = Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return user
    return checker


# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    password: str
    role: str = Field(default="Guest", pattern="^(Admin|Receptionist|Guest)$")


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: str
    createdAt: Optional[datetime] = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RoomCreate(BaseModel):
    roomNumber: str
    type: str
    price: float
    images: List[str] = []
    features: List[str] = []
    status: str = Field(default="Available")


class RoomOut(RoomCreate):
    id: str


class BookingCreate(BaseModel):
    guestId: str
    roomId: str
    checkIn: datetime
    checkOut: datetime
    totalAmount: float
    paymentStatus: str = "Pending"
    status: str = "Confirmed"


class BookingOut(BookingCreate):
    id: str


class ServiceRequestCreate(BaseModel):
    guestId: str
    type: str
    description: str
    status: str = "Pending"


class ServiceRequestOut(ServiceRequestCreate):
    id: str


class PaymentCreate(BaseModel):
    bookingId: str
    method: str
    amount: float
    status: str


class PaymentOut(PaymentCreate):
    id: str


# ----------------------------------------------------------------------------
# Basic health
# ----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "HMS API running"}


@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"status": "ok", "collections": collections}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ----------------------------------------------------------------------------
# Auth Routes
# ----------------------------------------------------------------------------
@app.post("/api/auth/register", response_model=UserOut)
def register(payload: UserCreate):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(400, "Email already registered")

    hashed = hash_password(payload.password)
    doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "phone": payload.phone,
        "password": hashed,
        "role": payload.role,
        "createdAt": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(doc)
    return UserOut(id=str(res.inserted_id), name=doc["name"], email=doc["email"], phone=doc.get("phone"), role=doc["role"], createdAt=doc["createdAt"]) 


@app.post("/api/auth/login", response_model=TokenOut)
def login(payload: UserLogin):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": str(user["_id"]), "role": user["role"]})
    return TokenOut(access_token=token)


@app.get("/api/auth/me", response_model=UserOut)
def me(user = Depends(get_current_user)):
    return UserOut(id=user["_id"], name=user["name"], email=user["email"], phone=user.get("phone"), role=user["role"], createdAt=user.get("createdAt"))


# ----------------------------------------------------------------------------
# Rooms
# ----------------------------------------------------------------------------
@app.post("/api/rooms", response_model=RoomOut)
def create_room(payload: RoomCreate, user = Depends(require_roles("Admin"))):
    doc = payload.model_dump()
    res = db["room"].insert_one(doc)
    return RoomOut(id=str(res.inserted_id), **payload.model_dump())


@app.get("/api/rooms", response_model=List[RoomOut])
def list_rooms():
    items = []
    for r in db["room"].find({}):
        r["id"] = str(r.pop("_id"))
        items.append(RoomOut(**r))
    return items


@app.get("/api/rooms/{id}", response_model=RoomOut)
def get_room(id: str):
    r = db["room"].find_one({"_id": ObjectId(id)})
    if not r:
        raise HTTPException(404, "Room not found")
    r["id"] = str(r.pop("_id"))
    return RoomOut(**r)


@app.put("/api/rooms/{id}", response_model=RoomOut)
def update_room(id: str, payload: RoomCreate, user = Depends(require_roles("Admin"))):
    db["room"].update_one({"_id": ObjectId(id)}, {"$set": payload.model_dump()})
    return get_room(id)


@app.delete("/api/rooms/{id}")
def delete_room(id: str, user = Depends(require_roles("Admin"))):
    db["room"].delete_one({"_id": ObjectId(id)})
    return {"deleted": True}


# ----------------------------------------------------------------------------
# Bookings
# ----------------------------------------------------------------------------
@app.post("/api/bookings", response_model=BookingOut)
def create_booking(payload: BookingCreate, user=Depends(get_current_user)):
    # Allow Guests and Receptionists/Admins to create bookings
    doc = payload.model_dump()
    res = db["booking"].insert_one(doc)
    return BookingOut(id=str(res.inserted_id), **doc)


@app.get("/api/bookings/user/{user_id}", response_model=List[BookingOut])
def bookings_by_user(user_id: str, user=Depends(get_current_user)):
    items = []
    for b in db["booking"].find({"guestId": user_id}):
        b["id"] = str(b.pop("_id"))
        items.append(BookingOut(**b))
    return items


@app.get("/api/bookings", response_model=List[BookingOut])
def list_bookings(user = Depends(require_roles("Admin", "Receptionist"))):
    items = []
    for b in db["booking"].find({}):
        b["id"] = str(b.pop("_id"))
        items.append(BookingOut(**b))
    return items


@app.delete("/api/bookings/{id}")
def delete_booking(id: str, user = Depends(require_roles("Admin", "Receptionist"))):
    db["booking"].delete_one({"_id": ObjectId(id)})
    return {"deleted": True}


# ----------------------------------------------------------------------------
# Service Requests
# ----------------------------------------------------------------------------
@app.post("/api/services", response_model=ServiceRequestOut)
def create_service(payload: ServiceRequestCreate, user=Depends(get_current_user)):
    doc = payload.model_dump()
    res = db["servicerequest"].insert_one(doc)
    return ServiceRequestOut(id=str(res.inserted_id), **doc)


@app.get("/api/services/user/{user_id}", response_model=List[ServiceRequestOut])
def services_by_user(user_id: str, user=Depends(get_current_user)):
    items = []
    for s in db["servicerequest"].find({"guestId": user_id}):
        s["id"] = str(s.pop("_id"))
        items.append(ServiceRequestOut(**s))
    return items


@app.put("/api/services/{id}", response_model=ServiceRequestOut)
def update_service(id: str, payload: ServiceRequestCreate, user = Depends(require_roles("Admin", "Receptionist"))):
    db["servicerequest"].update_one({"_id": ObjectId(id)}, {"$set": payload.model_dump()})
    s = db["servicerequest"].find_one({"_id": ObjectId(id)})
    s["id"] = str(s.pop("_id"))
    return ServiceRequestOut(**s)


# ----------------------------------------------------------------------------
# Payments
# ----------------------------------------------------------------------------
@app.post("/api/payments", response_model=PaymentOut)
def create_payment(payload: PaymentCreate, user=Depends(get_current_user)):
    doc = payload.model_dump()
    res = db["payment"].insert_one(doc)
    return PaymentOut(id=str(res.inserted_id), **doc)


@app.get("/api/payments/{booking_id}", response_model=List[PaymentOut])
def payments_by_booking(booking_id: str, user=Depends(get_current_user)):
    items = []
    for p in db["payment"].find({"bookingId": booking_id}):
        p["id"] = str(p.pop("_id"))
        items.append(PaymentOut(**p))
    return items


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
