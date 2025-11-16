from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

# Users: admin or staff
class Users(BaseModel):
    email: EmailStr
    password_hash: str
    name: str
    role: str = Field(..., pattern="^(admin|staff)$")
    is_active: bool = True

# Master Barang
class Barang(BaseModel):
    kode_barang: str
    nama_barang: str
    satuan: str = Field(..., pattern="^(Gram|Kg|Ml|Pcs)$")
    harga_beli_default: float = 0
    kategori: str = Field(..., pattern="^(Bahan Baku|Barang Jadi)$")

# Master Supplier
class Supplier(BaseModel):
    kode_supplier: str
    nama_supplier: str
    alamat: Optional[str] = None
    nomor_hp: Optional[str] = None

# Master Customer
class Customer(BaseModel):
    kode_customer: str
    nama_customer: str
    alamat: Optional[str] = None
    nomor_hp: Optional[str] = None

# Pembelian Bahan Baku (header + items)
class PembelianItem(BaseModel):
    kode_barang: str
    nama_barang: str
    satuan: str
    qty: float
    harga_beli: float

class Pembelian(BaseModel):
    nomor_faktur: str
    tanggal: str
    kode_supplier: str
    supplier_name: Optional[str] = None
    keterangan: Optional[str] = None
    items: List[PembelianItem]
    grand_total: float

# Barang Masuk
class BarangMasuk(BaseModel):
    tanggal: str
    kode_barang: str
    nama_barang: str
    satuan: str
    qty: float
    catatan: Optional[str] = None

# Barang Keluar
class BarangKeluar(BaseModel):
    tanggal: str
    kode_barang: str
    nama_barang: str
    satuan: str
    qty: float
    catatan: Optional[str] = None

# Penjualan
class PenjualanItem(BaseModel):
    kode_barang: str
    nama_barang: str
    satuan: str
    qty: float
    harga_jual: float

class Penjualan(BaseModel):
    nomor_penjualan: str
    tanggal: str
    kode_customer: str
    customer_name: Optional[str] = None
    keterangan: Optional[str] = None
    items: List[PenjualanItem]
    grand_total: float
