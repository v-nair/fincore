from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# Enums
class UserRole(str, Enum):
    CUSTOMER = "customer"
    ADMIN = "admin"
    COMPLIANCE = "compliance"


class AccountType(str, Enum):
    CHECKING = "checking"
    SAVINGS = "savings"
    INVESTMENT = "investment"
    BUSINESS = "business"


class AccountStatus(str, Enum):
    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"
    PENDING = "pending"


class TransactionType(str, Enum):
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER = "transfer"
    FEE = "fee"
    INTEREST = "interest"


class TransactionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REVERSED = "reversed"


class KYCDocumentType(str, Enum):
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    NATIONAL_ID = "national_id"
    UTILITY_BILL = "utility_bill"


class KYCStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class FraudAlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    phone: Optional[str] = Field(None, max_length=20)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)


class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone: Optional[str] = Field(None, max_length=20)
    mfa_enabled: Optional[bool] = None


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    role: UserRole
    is_active: bool
    email_verified: bool
    phone_verified: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_info: Optional[str] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    refresh_token: str


# KYC Schemas
class KYCDocumentCreate(BaseModel):
    document_type: KYCDocumentType
    document_number: Optional[str] = Field(None, max_length=100)
    issue_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None


class KYCDocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    document_type: KYCDocumentType
    file_path: str
    document_number: Optional[str]
    issue_date: Optional[datetime]
    expiry_date: Optional[datetime]
    status: KYCStatus
    verified_at: Optional[datetime]
    rejection_reason: Optional[str]
    created_at: datetime


# Account Schemas
class AccountCreate(BaseModel):
    account_type: AccountType
    currency: str = Field(default="CAD", pattern="^[A-Z]{3}$")


class AccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    account_number: str
    account_type: AccountType
    status: AccountStatus
    currency: str
    current_balance: Decimal
    available_balance: Decimal
    daily_transaction_limit: Decimal
    monthly_transaction_limit: Decimal
    opened_at: datetime
    closed_at: Optional[datetime]


class AccountBalance(BaseModel):
    account_number: str
    current_balance: Decimal
    available_balance: Decimal
    currency: str


# Transaction Schemas
class TransactionCreate(BaseModel):
    from_account_id: Optional[int] = None
    to_account_id: Optional[int] = None
    transaction_type: TransactionType
    amount: Decimal = Field(..., gt=0, decimal_places=4, max_digits=19)
    currency: str = Field(default="CAD", pattern="^[A-Z]{3}$")
    description: Optional[str] = Field(None, max_length=255)
    external_reference: Optional[str] = Field(None, max_length=100)
    idempotency_key: Optional[str] = Field(None, max_length=100)


class TransactionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    transaction_reference: str
    from_account_id: Optional[int]
    to_account_id: Optional[int]
    transaction_type: TransactionType
    status: TransactionStatus
    amount: Decimal
    currency: str
    exchange_rate: Decimal
    fee_amount: Decimal
    description: Optional[str]
    external_reference: Optional[str]
    executed_at: Optional[datetime]
    created_at: datetime


class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: Decimal = Field(..., gt=0, decimal_places=4, max_digits=19)
    description: Optional[str] = Field(None, max_length=255)
    idempotency_key: Optional[str] = Field(None, max_length=100)


class DepositRequest(BaseModel):
    to_account_id: int
    amount: Decimal = Field(..., gt=0, decimal_places=4, max_digits=19)
    description: Optional[str] = Field(None, max_length=255)
    idempotency_key: Optional[str] = Field(None, max_length=100)


class WithdrawalRequest(BaseModel):
    from_account_id: int
    amount: Decimal = Field(..., gt=0, decimal_places=4, max_digits=19)
    description: Optional[str] = Field(None, max_length=255)
    idempotency_key: Optional[str] = Field(None, max_length=100)


class TransactionHistory(BaseModel):
    transactions: List[TransactionResponse]
    total_count: int
    page: int
    page_size: int


# Ledger Schemas
class LedgerEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    transaction_id: int
    debit_account_id: Optional[int]
    credit_account_id: Optional[int]
    amount: Decimal
    entry_date: datetime
    description: Optional[str]


# Fraud Alert Schemas
class FraudAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    transaction_id: int
    rule_triggered: str
    risk_score: Decimal
    status: FraudAlertStatus
    details: Optional[str]
    created_at: datetime
    reviewed_at: Optional[datetime]
    resolution_notes: Optional[str]


class FraudAlertReview(BaseModel):
    status: FraudAlertStatus
    resolution_notes: Optional[str] = None


# Statement Schema
class StatementRequest(BaseModel):
    account_id: int
    start_date: datetime
    end_date: datetime


# Admin Schemas
class AdminUserUpdate(BaseModel):
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None
    email_verified: Optional[bool] = None


class AdminAccountUpdate(BaseModel):
    status: Optional[AccountStatus] = None
    daily_transaction_limit: Optional[Decimal] = None
    monthly_transaction_limit: Optional[Decimal] = None


class AccountFreezeRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class AccountUnfreezeRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)
