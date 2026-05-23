from datetime import datetime
from decimal import Decimal
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Numeric, ForeignKey, Enum, 
    Boolean, Text, Index, UniqueConstraint, CheckConstraint
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(AsyncAttrs, DeclarativeBase):
    pass


class UserRole(PyEnum):
    CUSTOMER = "customer"
    ADMIN = "admin"
    COMPLIANCE = "compliance"


class AccountType(PyEnum):
    CHECKING = "checking"
    SAVINGS = "savings"
    INVESTMENT = "investment"
    BUSINESS = "business"


class AccountStatus(PyEnum):
    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"
    PENDING = "pending"


class TransactionType(PyEnum):
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER = "transfer"
    FEE = "fee"
    INTEREST = "interest"


class TransactionStatus(PyEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REVERSED = "reversed"


class KYCDocumentType(PyEnum):
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    NATIONAL_ID = "national_id"
    UTILITY_BILL = "utility_bill"


class KYCStatus(PyEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class FraudAlertStatus(PyEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    phone = Column(String(20), unique=True, index=True)
    role = Column(Enum(UserRole), default=UserRole.CUSTOMER, nullable=False)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    phone_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    accounts = relationship("Account", back_populates="user", lazy="selectin")
    kyc_documents = relationship("KYCDocument", back_populates="user", lazy="selectin")
    sessions = relationship("UserSession", back_populates="user", lazy="selectin")
    
    __table_args__ = (
        Index('idx_user_email_active', 'email', 'is_active'),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token = Column(String(255), unique=True, nullable=False)
    device_info = Column(String(255))
    ip_address = Column(String(45))
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="sessions")
    
    __table_args__ = (
        Index('idx_session_token', 'refresh_token'),
        Index('idx_session_user', 'user_id', 'revoked'),
    )


class KYCDocument(Base):
    __tablename__ = "kyc_documents"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    document_type = Column(Enum(KYCDocumentType), nullable=False)
    file_path = Column(String(500), nullable=False)
    document_number = Column(String(100))
    issue_date = Column(DateTime)
    expiry_date = Column(DateTime)
    status = Column(Enum(KYCStatus), default=KYCStatus.PENDING)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime)
    rejection_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="kyc_documents", foreign_keys=[user_id])


class Account(Base):
    __tablename__ = "accounts"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    account_number = Column(String(20), unique=True, index=True, nullable=False)
    account_type = Column(Enum(AccountType), nullable=False)
    status = Column(Enum(AccountStatus), default=AccountStatus.ACTIVE)
    currency = Column(String(3), default="CAD", nullable=False)
    current_balance = Column(Numeric(19, 4), default=Decimal("0.0000"))
    available_balance = Column(Numeric(19, 4), default=Decimal("0.0000"))
    daily_transaction_limit = Column(Numeric(19, 4), default=Decimal("10000.0000"))
    monthly_transaction_limit = Column(Numeric(19, 4), default=Decimal("100000.0000"))
    opened_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)
    
    user = relationship("User", back_populates="accounts")
    debit_entries = relationship("LedgerEntry", foreign_keys="LedgerEntry.debit_account_id", lazy="selectin")
    credit_entries = relationship("LedgerEntry", foreign_keys="LedgerEntry.credit_account_id", lazy="selectin")
    
    __table_args__ = (
        Index('idx_account_user_type', 'user_id', 'account_type'),
        Index('idx_account_status', 'status'),
    )


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    
    id = Column(Integer, primary_key=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"), nullable=False)
    debit_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    credit_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    amount = Column(Numeric(19, 4), nullable=False)
    entry_date = Column(DateTime, default=datetime.utcnow)
    description = Column(String(255))
    
    transaction = relationship("Transaction", back_populates="ledger_entries")
    debit_account = relationship("Account", foreign_keys=[debit_account_id])
    credit_account = relationship("Account", foreign_keys=[credit_account_id])
    
    __table_args__ = (
        CheckConstraint(
            '(debit_account_id IS NOT NULL) OR (credit_account_id IS NOT NULL)',
            name='check_account_present'
        ),
        Index('idx_ledger_transaction', 'transaction_id'),
        Index('idx_ledger_debit', 'debit_account_id', 'entry_date'),
        Index('idx_ledger_credit', 'credit_account_id', 'entry_date'),
    )


class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(Integer, primary_key=True)
    transaction_reference = Column(String(50), unique=True, index=True, nullable=False)
    from_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    to_account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    transaction_type = Column(Enum(TransactionType), nullable=False)
    status = Column(Enum(TransactionStatus), default=TransactionStatus.PENDING)
    amount = Column(Numeric(19, 4), nullable=False)
    currency = Column(String(3), default="CAD")
    exchange_rate = Column(Numeric(19, 8), default=Decimal("1.00000000"))
    fee_amount = Column(Numeric(19, 4), default=Decimal("0.0000"))
    description = Column(String(255))
    external_reference = Column(String(100))
    ip_address = Column(String(45))
    device_info = Column(String(255))
    executed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    idempotency_key = Column(String(100), unique=True, index=True)
    
    from_account = relationship("Account", foreign_keys=[from_account_id])
    to_account = relationship("Account", foreign_keys=[to_account_id])
    ledger_entries = relationship("LedgerEntry", back_populates="transaction", lazy="selectin")
    fraud_alerts = relationship("FraudAlert", back_populates="transaction", lazy="selectin")
    
    __table_args__ = (
        Index('idx_txn_from_status', 'from_account_id', 'status'),
        Index('idx_txn_to_status', 'to_account_id', 'status'),
        Index('idx_txn_created', 'created_at'),
        Index('idx_txn_idempotency', 'idempotency_key'),
    )


class FraudAlert(Base):
    __tablename__ = "fraud_alerts"
    
    id = Column(Integer, primary_key=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"), nullable=False)
    rule_triggered = Column(String(100), nullable=False)
    risk_score = Column(Numeric(5, 2), nullable=False)
    status = Column(Enum(FraudAlertStatus), default=FraudAlertStatus.OPEN)
    details = Column(Text)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime)
    resolution_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    transaction = relationship("Transaction", back_populates="fraud_alerts")
    
    __table_args__ = (
        Index('idx_fraud_status', 'status'),
        Index('idx_fraud_risk', 'risk_score', 'status'),
    )
