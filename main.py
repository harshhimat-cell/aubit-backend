from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Float, Boolean, DateTime, ForeignKey, Text, Enum as SAEnum, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr, validator
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
import uuid, os, enum
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aubit.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserRole(str, enum.Enum):
    user = "user"
    admin = "admin"

class User(Base):
    __tablename__ = "users"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email           = Column(String, unique=True, index=True, nullable=False)
    full_name       = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="user")
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    vault           = relationship("Vault", back_populates="user", uselist=False)
    transactions    = relationship("Transaction", back_populates="user")

class WaitlistEntry(Base):
    __tablename__ = "waitlist"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email       = Column(String, unique=True, index=True, nullable=False)
    name        = Column(String, nullable=True)
    is_investor = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)

class Vault(Base):
    __tablename__ = "vaults"
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, ForeignKey("users.id"), unique=True)
    pct_bgci   = Column(Float, default=40.0)
    pct_btc    = Column(Float, default=35.0)
    pct_btcgold= Column(Float, default=0.0)
    pct_gold   = Column(Float, default=25.0)
    val_bgci   = Column(Float, default=0.0)
    val_btc    = Column(Float, default=0.0)
    val_btcgold= Column(Float, default=0.0)
    val_gold   = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    user       = relationship("User", back_populates="vault")

    @property
    def total(self):
        return self.val_bgci + self.val_btc + self.val_btcgold + self.val_gold

class Transaction(Base):
    __tablename__ = "transactions"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(String, ForeignKey("users.id"))
    merchant      = Column(String, nullable=False)
    amount_inr    = Column(Float, nullable=False)
    reward_inr    = Column(Float, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    user          = relationship("User", back_populates="transactions")

Base.metadata.create_all(bind=engine)

SECRET_KEY   = os.getenv("SECRET_KEY", "aubit-secret-change-in-production-2025")
ALGORITHM    = "HS256"
pwd_context  = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme= OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(p): return pwd_context.hash(p)
def verify_password(p, h): return pwd_context.verify(p, h)
def create_token(uid): return jwt.encode({"sub": uid, "exp": datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        uid = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except:
        raise HTTPException(401, "Invalid token")
    user = db.query(User).filter(User.id == uid).first()
    if not user: raise HTTPException(401, "User not found")
    return user

app = FastAPI(title="AuBit API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root(): return {"status": "AuBit API is live"}

@app.get("/health")
def health(): return {"status": "ok"}

class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str
    password: str

@app.post("/auth/register", status_code=201, tags=["Auth"])
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(email=data.email, full_name=data.full_name, hashed_password=hash_password(data.password))
    db.add(user)
    db.flush()
    db.add(Vault(user_id=user.id))
    db.commit()
    return {"access_token": create_token(user.id), "token_type": "bearer", "full_name": user.full_name}

@app.post("/auth/login", tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": create_token(user.id), "token_type": "bearer", "full_name": user.full_name}

@app.get("/auth/me", tags=["Auth"])
def me(u: User = Depends(get_current_user)):
    return {"id": u.id, "email": u.email, "full_name": u.full_name}

@app.post("/waitlist/join", status_code=201, tags=["Waitlist"])
def join(email: str, name: str = None, is_investor: bool = False, db: Session = Depends(get_db)):
    if db.query(WaitlistEntry).filter(WaitlistEntry.email == email).first():
        raise HTTPException(400, "Already on waitlist")
    e = WaitlistEntry(email=email, name=name, is_investor=is_investor)
    db.add(e); db.commit()
    return {"position": db.query(WaitlistEntry).count(), "message": "Added to waitlist"}

@app.get("/vault", tags=["Vault"])
def get_vault(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(Vault).filter(Vault.user_id == u.id).first()
    if not v: raise HTTPException(404, "Vault not found")
    return {"allocation": {"bgci": v.pct_bgci, "btc": v.pct_btc, "btc_gold": v.pct_btcgold, "gold": v.pct_gold},
            "balances": {"bgci": round(v.val_bgci,2), "btc": round(v.val_btc,2), "btc_gold": round(v.val_btcgold,2), "gold": round(v.val_gold,2)},
            "total_inr": round(v.total, 2)}

@app.put("/vault/allocation", tags=["Vault"])
def update_vault(bgci: float, btc: float, btc_gold: float, gold: float, u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if abs(bgci + btc + btc_gold + gold - 100) > 0.1:
        raise HTTPException(400, "Allocations must sum to 100")
    v = db.query(Vault).filter(Vault.user_id == u.id).first()
    v.pct_bgci, v.pct_btc, v.pct_btcgold, v.pct_gold = bgci, btc, btc_gold, gold
    db.commit()
    return {"message": "Allocation updated"}

@app.post("/rewards/transact", status_code=201, tags=["Rewards"])
def transact(merchant: str, amount_inr: float, u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if amount_inr <= 0: raise HTTPException(400, "Amount must be positive")
    v = db.query(Vault).filter(Vault.user_id == u.id).first()
    reward = round(amount_inr * 0.005, 2)
    v.val_bgci   += round(reward * v.pct_bgci    / 100, 4)
    v.val_btc    += round(reward * v.pct_btc     / 100, 4)
    v.val_btcgold+= round(reward * v.pct_btcgold / 100, 4)
    v.val_gold   += round(reward * v.pct_gold    / 100, 4)
    db.add(Transaction(user_id=u.id, merchant=merchant, amount_inr=amount_inr, reward_inr=reward))
    db.commit()
    return {"reward_earned": reward, "message": "Transaction recorded"}

@app.get("/rewards/history", tags=["Rewards"])
def history(u: User = Depends(get_current_user), db: Session = Depends(get_db)):
    txns = db.query(Transaction).filter(Transaction.user_id == u.id).order_by(Transaction.created_at.desc()).limit(50).all()
    return [{"merchant": t.merchant, "amount": t.amount_inr, "reward": t.reward_inr, "date": str(t.created_at)} for t in txns]

@app.get("/admin/stats", tags=["Admin"])
def stats(db: Session = Depends(get_db)):
    return {"users": db.query(User).count(), "waitlist": db.query(WaitlistEntry).count(),
            "transactions": db.query(Transaction).count(),
            "total_rewards": round(db.query(func.sum(Transaction.reward_inr)).scalar() or 0, 2)}

@app.get("/admin/waitlist", tags=["Admin"])
def waitlist(db: Session = Depends(get_db)):
    return [{"email": e.email, "name": e.name, "is_investor": e.is_investor, "joined": str(e.created_at)} for e in db.query(WaitlistEntry).all()]
