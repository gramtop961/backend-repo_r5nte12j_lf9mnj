import os
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import Users, Barang, Supplier, Customer, Pembelian, BarangMasuk, BarangKeluar, Penjualan

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="SAE Bakery – SOP API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def collection(name: str):
    return db[name]

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str  # admin only can create users, enforced by route

# Auth utilities

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def get_current_user(token: str = Query(None, alias="token")):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = collection("users").find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

# Bootstrap admin if not exists
@app.on_event("startup")
async def ensure_admin():
    if collection("users").count_documents({"role": "admin"}) == 0:
        collection("users").insert_one({
            "email": "admin@sae-bakery.local",
            "password_hash": get_password_hash("admin123"),
            "name": "Admin",
            "role": "admin",
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })

# Public
@app.get("/")
def root():
    return {"app": "SAE Bakery – SOP API", "status": "ok"}

@app.get("/test")
def test_database():
    try:
        names = db.list_collection_names()
        return {"database": "connected", "collections": names}
    except Exception as e:
        return {"database": f"error: {e}"}

# Auth endpoints
@app.post("/api/auth/login", response_model=Token)
def login(req: LoginRequest):
    user = collection("users").find_one({"email": req.email})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email atau password salah")
    token = create_access_token({"sub": req.email, "role": user.get("role")})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/register")
def register(req: RegisterRequest, current=Depends(get_current_user)):
    require_admin(current)
    if collection("users").find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    doc = Users(
        email=req.email,
        password_hash=get_password_hash(req.password),
        name=req.name,
        role=req.role,
        is_active=True,
    )
    create_document("users", doc)
    return {"message": "User berhasil dibuat"}

# Utility for auto codes

def next_code(prefix: str, pad: int = 3, field: str = None, coll: str = None):
    c = coll or prefix.lower()
    f = field or f"kode_{c}"
    last = collection(c).find_one({f: {"$regex": f"^{prefix}"}}, sort=[(f, -1)])
    if not last:
        num = 1
    else:
        # Extract trailing digits
        import re
        m = re.search(r"(\d+)$", last[f])
        num = int(m.group(1)) + 1 if m else 1
    return f"{prefix}{str(num).zfill(pad)}"

# Master Data: Barang
@app.post("/api/barang")
def create_barang(data: Barang, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa membuat master data")
    # Uniqueness
    if collection("barang").find_one({"kode_barang": data.kode_barang}):
        raise HTTPException(status_code=400, detail="Kode barang sudah ada")
    create_document("barang", data)
    return {"message": "Barang dibuat"}

@app.get("/api/barang")
def list_barang(q: Optional[str] = None, page: int = 1, size: int = 50, current=Depends(get_current_user)):
    filt = {}
    if q:
        filt = {"$or": [
            {"nama_barang": {"$regex": q, "$options": "i"}},
            {"kode_barang": {"$regex": q, "$options": "i"}}
        ]}
    docs = collection("barang").find(filt).skip((page-1)*size).limit(size)
    return [
        {"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}}
        for d in docs
    ]

# Master: Supplier
@app.post("/api/supplier")
def create_supplier(data: Supplier, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa membuat master data")
    if collection("supplier").find_one({"kode_supplier": data.kode_supplier}):
        raise HTTPException(status_code=400, detail="Kode supplier sudah ada")
    create_document("supplier", data)
    return {"message": "Supplier dibuat"}

@app.get("/api/supplier")
def list_supplier(q: Optional[str] = None, page: int = 1, size: int = 50, current=Depends(get_current_user)):
    filt = {}
    if q:
        filt = {"$or": [
            {"nama_supplier": {"$regex": q, "$options": "i"}},
            {"kode_supplier": {"$regex": q, "$options": "i"}}
        ]}
    docs = collection("supplier").find(filt).skip((page-1)*size).limit(size)
    return [
        {"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}}
        for d in docs
    ]

# Master: Customer
@app.post("/api/customer")
def create_customer(data: Customer, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa membuat master data")
    if collection("customer").find_one({"kode_customer": data.kode_customer}):
        raise HTTPException(status_code=400, detail="Kode customer sudah ada")
    create_document("customer", data)
    return {"message": "Customer dibuat"}

@app.get("/api/customer")
def list_customer(q: Optional[str] = None, page: int = 1, size: int = 50, current=Depends(get_current_user)):
    filt = {}
    if q:
        filt = {"$or": [
            {"nama_customer": {"$regex": q, "$options": "i"}},
            {"kode_customer": {"$regex": q, "$options": "i"}}
        ]}
    docs = collection("customer").find(filt).skip((page-1)*size).limit(size)
    return [
        {"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}}
        for d in docs
    ]

# Autocomplete endpoints (debounce handled on FE)
@app.get("/api/supplier/search")
def supplier_search(term: str, current=Depends(get_current_user)):
    docs = collection("supplier").find({
        "$or": [
            {"nama_supplier": {"$regex": term, "$options": "i"}},
            {"kode_supplier": {"$regex": term, "$options": "i"}},
        ]
    }).limit(10)
    return [{
        "id": str(d.get("_id")),
        "nama_supplier": d.get("nama_supplier"),
        "kode_supplier": d.get("kode_supplier"),
    } for d in docs]

@app.get("/api/barang/search")
def barang_search(term: str, current=Depends(get_current_user)):
    docs = collection("barang").find({
        "$or": [
            {"nama_barang": {"$regex": term, "$options": "i"}},
            {"kode_barang": {"$regex": term, "$options": "i"}},
        ]
    }).limit(10)
    return [{
        "id": str(d.get("_id")),
        "nama_barang": d.get("nama_barang"),
        "kode_barang": d.get("kode_barang"),
        "satuan": d.get("satuan"),
        "harga_beli_default": d.get("harga_beli_default", 0),
    } for d in docs]

@app.get("/api/customer/search")
def customer_search(term: str, current=Depends(get_current_user)):
    docs = collection("customer").find({
        "$or": [
            {"nama_customer": {"$regex": term, "$options": "i"}},
            {"kode_customer": {"$regex": term, "$options": "i"}},
        ]
    }).limit(10)
    return [{
        "id": str(d.get("_id")),
        "nama_customer": d.get("nama_customer"),
        "kode_customer": d.get("kode_customer"),
    } for d in docs]

# Transactions
@app.post("/api/transaksi/pembelian")
def create_pembelian(data: Pembelian, current=Depends(get_current_user)):
    # Validate supplier exists
    sup = collection("supplier").find_one({"kode_supplier": data.kode_supplier})
    if not sup:
        raise HTTPException(status_code=400, detail="Supplier tidak ditemukan")
    # Validate items exist
    for it in data.items:
        br = collection("barang").find_one({"kode_barang": it.kode_barang})
        if not br:
            raise HTTPException(status_code=400, detail=f"Barang {it.kode_barang} tidak ditemukan")
    # Save header
    create_document("pembelian", data)
    # Update stock from purchase (increase)
    for it in data.items:
        collection("stock").update_one(
            {"kode_barang": it.kode_barang},
            {"$inc": {"stok": it.qty}, "$setOnInsert": {"satuan": it.satuan, "nama_barang": it.nama_barang}},
            upsert=True,
        )
    return {"message": "Pembelian disimpan"}

@app.post("/api/transaksi/barang-masuk")
def create_barang_masuk(data: BarangMasuk, current=Depends(get_current_user)):
    br = collection("barang").find_one({"kode_barang": data.kode_barang})
    if not br:
        raise HTTPException(status_code=400, detail="Barang tidak ditemukan")
    create_document("barangmasuk", data)
    collection("stock").update_one(
        {"kode_barang": data.kode_barang},
        {"$inc": {"stok": data.qty}, "$setOnInsert": {"satuan": data.satuan, "nama_barang": data.nama_barang}},
        upsert=True,
    )
    return {"message": "Barang masuk disimpan"}

@app.post("/api/transaksi/barang-keluar")
def create_barang_keluar(data: BarangKeluar, current=Depends(get_current_user)):
    br = collection("barang").find_one({"kode_barang": data.kode_barang})
    if not br:
        raise HTTPException(status_code=400, detail="Barang tidak ditemukan")
    # ensure stock sufficient
    st = collection("stock").find_one({"kode_barang": data.kode_barang})
    if st and st.get("stok", 0) < data.qty:
        raise HTTPException(status_code=400, detail="Stok tidak mencukupi")
    create_document("barngkeluar", data)
    collection("stock").update_one(
        {"kode_barang": data.kode_barang},
        {"$inc": {"stok": -data.qty}, "$setOnInsert": {"satuan": data.satuan, "nama_barang": data.nama_barang}},
        upsert=True,
    )
    return {"message": "Barang keluar disimpan"}

@app.post("/api/transaksi/penjualan")
def create_penjualan(data: Penjualan, current=Depends(get_current_user)):
    cust = collection("customer").find_one({"kode_customer": data.kode_customer})
    if not cust:
        raise HTTPException(status_code=400, detail="Customer tidak ditemukan")
    # validate items & stock
    for it in data.items:
        br = collection("barang").find_one({"kode_barang": it.kode_barang})
        if not br:
            raise HTTPException(status_code=400, detail=f"Barang {it.kode_barang} tidak ditemukan")
        st = collection("stock").find_one({"kode_barang": it.kode_barang})
        if st and st.get("stok", 0) < it.qty:
            raise HTTPException(status_code=400, detail=f"Stok {it.kode_barang} tidak mencukupi")
    create_document("penjualan", data)
    for it in data.items:
        collection("stock").update_one(
            {"kode_barang": it.kode_barang},
            {"$inc": {"stok": -it.qty}, "$setOnInsert": {"satuan": it.satuan, "nama_barang": it.nama_barang}},
            upsert=True,
        )
    return {"message": "Penjualan disimpan"}

# Reports
@app.get("/api/laporan/pembelian")
def laporan_pembelian(tanggal: Optional[str] = None, supplier: Optional[str] = None, current=Depends(get_current_user)):
    filt = {}
    if tanggal:
        filt["tanggal"] = tanggal
    if supplier:
        filt["kode_supplier"] = supplier
    docs = collection("pembelian").find(filt)
    return [
        {"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}}
        for d in docs
    ]

@app.get("/api/laporan/barang-masuk")
def laporan_masuk(tanggal: Optional[str] = None, nama: Optional[str] = None, current=Depends(get_current_user)):
    filt = {}
    if tanggal:
        filt["tanggal"] = tanggal
    if nama:
        filt["nama_barang"] = {"$regex": nama, "$options": "i"}
    docs = collection("barangmasuk").find(filt)
    return [{"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}} for d in docs]

@app.get("/api/laporan/barang-keluar")
def laporan_keluar(tanggal: Optional[str] = None, nama: Optional[str] = None, current=Depends(get_current_user)):
    filt = {}
    if tanggal:
        filt["tanggal"] = tanggal
    if nama:
        filt["nama_barang"] = {"$regex": nama, "$options": "i"}
    docs = collection("barngkeluar").find(filt)
    return [{"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}} for d in docs]

@app.get("/api/laporan/penjualan")
def laporan_penjualan(tanggal: Optional[str] = None, customer: Optional[str] = None, current=Depends(get_current_user)):
    filt = {}
    if tanggal:
        filt["tanggal"] = tanggal
    if customer:
        filt["kode_customer"] = customer
    docs = collection("penjualan").find(filt)
    return [{"id": str(d.get("_id")), **{k: v for k, v in d.items() if k != "_id"}} for d in docs]

@app.get("/api/laporan/stock")
def laporan_stock(current=Depends(get_current_user)):
    docs = collection("stock").find({})
    return [
        {
            "kode_barang": d.get("kode_barang"),
            "nama_barang": d.get("nama_barang"),
            "stok_total": d.get("stok", 0),
            "satuan": d.get("satuan"),
        } for d in docs
    ]

# Auto-code helpers endpoints
@app.get("/api/autocode/barang")
def autocode_barang(current=Depends(get_current_user)):
    code = next_code("KODE-", pad=3, field="kode_barang", coll="barang")
    return {"kode": code}

@app.get("/api/autocode/supplier")
def autocode_supplier(current=Depends(get_current_user)):
    code = next_code("SUP", pad=3, field="kode_supplier", coll="supplier")
    return {"kode": code}

@app.get("/api/autocode/customer")
def autocode_customer(current=Depends(get_current_user)):
    code = next_code("CUS", pad=3, field="kode_customer", coll="customer")
    return {"kode": code}

@app.get("/api/autocode/invoice")
def autocode_invoice(current=Depends(get_current_user)):
    code = next_code("INV-", pad=3, field="nomor_faktur", coll="pembelian")
    return {"kode": code}

@app.get("/api/autocode/sales")
def autocode_sales(current=Depends(get_current_user)):
    code = next_code("SL-", pad=3, field="nomor_penjualan", coll="penjualan")
    return {"kode": code}
