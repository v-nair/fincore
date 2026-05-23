from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, List
import os
import uuid

from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import init_db, get_db
from app.config import settings
from app.redis_client import init_redis, close_redis
from app.kafka_producer import init_kafka, close_kafka
from app.auth import (
    authenticate_user,
    create_tokens,
    get_current_user,
    get_password_hash,
    verify_refresh_token,
    revoke_refresh_token,
    revoke_all_user_sessions,
    create_user_session,
    check_admin_access,
    check_compliance_access,
)
from app.models import (
    User, UserRole, UserSession, Account, AccountType, AccountStatus,
    Transaction, TransactionType, TransactionStatus, LedgerEntry,
    KYCDocument, KYCDocumentType, KYCStatus, FraudAlert, FraudAlertStatus
)
from app.schemas import (
    UserCreate, UserResponse, UserLogin, Token, TokenRefresh,
    AccountCreate, AccountResponse, AccountBalance,
    TransferRequest, DepositRequest, WithdrawalRequest,
    TransactionResponse, TransactionHistory,
    KYCDocumentCreate, KYCDocumentResponse,
    FraudAlertResponse, FraudAlertReview,
    StatementRequest,
    AdminUserUpdate, AdminAccountUpdate, AccountFreezeRequest, AccountUnfreezeRequest,
)
from app.fraud_detection import evaluate_transaction, create_fraud_alert
from app.kafka_producer import publish_transaction_event
from app.pdf_generator import generate_account_statement
from app.redis_client import check_rate_limit

# Security
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    await init_redis()
    await init_kafka()
    
    # Create directories
    os.makedirs(settings.kyc_documents_path, exist_ok=True)
    os.makedirs(settings.statements_path, exist_ok=True)
    
    yield
    
    # Shutdown
    await close_redis()
    await close_kafka()


app = FastAPI(
    title="FinCore - Core Banking Platform",
    description="Production-grade core banking system with fraud detection",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utility functions
async def get_db_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    user = await get_current_user(db, credentials.credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return user


def generate_account_number() -> str:
    """Generate unique account number"""
    return f"FC{uuid.uuid4().hex[:12].upper()}"


def generate_transaction_reference() -> str:
    """Generate unique transaction reference"""
    return f"TXN{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6].upper()}"


async def check_account_ownership(db: AsyncSession, account_id: int, user_id: int, admin_ok: bool = False) -> Account:
    """Verify user owns the account or is admin"""
    result = await db.execute(
        select(Account).where(Account.id == account_id)
    )
    account = result.scalar_one_or_none()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Admin can access any account
    if admin_ok:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one()
        if check_admin_access(user):
            return account
    
    if account.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this account")
    
    if account.status == AccountStatus.FROZEN:
        raise HTTPException(status_code=400, detail="Account is frozen")
    
    if account.status == AccountStatus.CLOSED:
        raise HTTPException(status_code=400, detail="Account is closed")
    
    return account


# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "fincore-api"}


# Authentication endpoints
@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if phone exists
    if user_data.phone:
        result = await db.execute(select(User).where(User.phone == user_data.phone))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Phone number already registered")
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        phone=user_data.phone,
        role=UserRole.CUSTOMER
    )
    db.add(user)
    await db.flush()
    
    return user


@app.post("/auth/login", response_model=Token)
async def login(
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db),
    x_forwarded_for: Optional[str] = Header(None)
):
    # Rate limiting check
    allowed, remaining = await check_rate_limit(
        f"login:{login_data.email}",
        5,  # 5 attempts
        300  # 5 minutes
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )
    
    user = await authenticate_user(db, login_data.email, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    
    # Create tokens
    tokens = create_tokens(user.id)
    
    # Store refresh token session
    ip_address = x_forwarded_for
    await create_user_session(
        db, user.id, tokens.refresh_token,
        device_info=login_data.device_info,
        ip_address=ip_address
    )
    
    await db.commit()
    return tokens


@app.post("/auth/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh,
    db: AsyncSession = Depends(get_db)
):
    user = await verify_refresh_token(db, token_data.refresh_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Revoke old token
    await revoke_refresh_token(db, token_data.refresh_token)
    
    # Create new tokens
    tokens = create_tokens(user.id)
    await create_user_session(db, user.id, tokens.refresh_token)
    
    await db.commit()
    return tokens


@app.post("/auth/logout")
async def logout(
    token_data: TokenRefresh,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    await revoke_refresh_token(db, token_data.refresh_token)
    await db.commit()
    return {"message": "Successfully logged out"}


@app.post("/auth/logout-all")
async def logout_all(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    count = await revoke_all_user_sessions(db, current_user.id)
    await db.commit()
    return {"message": f"Revoked {count} sessions"}


# User endpoints
@app.get("/users/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_db_user)):
    return current_user


# Account endpoints
@app.post("/accounts", response_model=AccountResponse)
async def create_account(
    account_data: AccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    # Check KYC status
    result = await db.execute(
        select(KYCDocument).where(
            KYCDocument.user_id == current_user.id,
            KYCDocument.status == KYCStatus.VERIFIED
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="KYC verification required before opening an account"
        )
    
    account = Account(
        user_id=current_user.id,
        account_number=generate_account_number(),
        account_type=account_data.account_type,
        currency=account_data.currency,
        status=AccountStatus.ACTIVE
    )
    db.add(account)
    await db.flush()
    
    return account


@app.get("/accounts", response_model=List[AccountResponse])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    result = await db.execute(
        select(Account).where(Account.user_id == current_user.id)
    )
    return result.scalars().all()


@app.get("/accounts/{account_id}", response_model=AccountResponse)
async def get_account(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    account = await check_account_ownership(db, account_id, current_user.id)
    return account


@app.get("/accounts/{account_id}/balance", response_model=AccountBalance)
async def get_balance(
    account_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    account = await check_account_ownership(db, account_id, current_user.id)
    return {
        "account_number": account.account_number,
        "current_balance": account.current_balance,
        "available_balance": account.available_balance,
        "currency": account.currency
    }


# Transaction endpoints
async def create_double_entry_transaction(
    db: AsyncSession,
    from_account: Optional[Account],
    to_account: Optional[Account],
    amount: Decimal,
    transaction_type: TransactionType,
    description: Optional[str],
    idempotency_key: Optional[str],
    ip_address: Optional[str],
    device_info: Optional[str],
    user_id: int
) -> Transaction:
    """Create a transaction with double-entry bookkeeping"""
    
    # Check idempotency
    if idempotency_key:
        result = await db.execute(
            select(Transaction).where(Transaction.idempotency_key == idempotency_key)
        )
        if result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Transaction already processed")
    
    # Create transaction record
    txn = Transaction(
        transaction_reference=generate_transaction_reference(),
        from_account_id=from_account.id if from_account else None,
        to_account_id=to_account.id if to_account else None,
        transaction_type=transaction_type,
        status=TransactionStatus.PENDING,
        amount=amount,
        currency=from_account.currency if from_account else (to_account.currency if to_account else "CAD"),
        description=description,
        ip_address=ip_address,
        device_info=device_info,
        idempotency_key=idempotency_key
    )
    db.add(txn)
    await db.flush()
    
    # Create ledger entries (double-entry)
    ledger_entries = []
    
    if from_account:
        # Debit from account
        entry = LedgerEntry(
            transaction_id=txn.id,
            debit_account_id=from_account.id,
            amount=amount,
            description=f"Debit: {description}"
        )
        ledger_entries.append(entry)
        from_account.current_balance -= amount
        from_account.available_balance -= amount
    
    if to_account:
        # Credit to account
        entry = LedgerEntry(
            transaction_id=txn.id,
            credit_account_id=to_account.id,
            amount=amount,
            description=f"Credit: {description}"
        )
        ledger_entries.append(entry)
        to_account.current_balance += amount
        to_account.available_balance += amount
    
    for entry in ledger_entries:
        db.add(entry)
    
    # Update transaction status
    txn.status = TransactionStatus.COMPLETED
    txn.executed_at = datetime.utcnow()
    
    return txn


@app.post("/transactions/transfer", response_model=TransactionResponse)
async def transfer(
    transfer_data: TransferRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user),
    x_forwarded_for: Optional[str] = Header(None),
    user_agent: Optional[str] = Header(None)
):
    # Get accounts
    from_account = await check_account_ownership(db, transfer_data.from_account_id, current_user.id)
    
    result = await db.execute(
        select(Account).where(
            Account.id == transfer_data.to_account_id,
            Account.status == AccountStatus.ACTIVE
        )
    )
    to_account = result.scalar_one_or_none()
    if not to_account:
        raise HTTPException(status_code=404, detail="Destination account not found or inactive")
    
    # Check sufficient funds
    if from_account.available_balance < transfer_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    
    # Check limits
    if transfer_data.amount > from_account.daily_transaction_limit:
        raise HTTPException(status_code=400, detail="Amount exceeds daily transaction limit")
    
    # Fraud detection
    is_suspicious, risk_score, triggered_rules = await evaluate_transaction(
        db, current_user.id, from_account.id, to_account.id,
        transfer_data.amount, x_forwarded_for, user_agent
    )
    
    # Create transaction
    txn = await create_double_entry_transaction(
        db, from_account, to_account, transfer_data.amount,
        TransactionType.TRANSFER, transfer_data.description,
        transfer_data.idempotency_key, x_forwarded_for, user_agent,
        current_user.id
    )
    
    # Create fraud alert if suspicious
    if is_suspicious:
        for rule in triggered_rules:
            await create_fraud_alert(
                db, txn.id, rule['rule'], rule['risk_score'],
                f"{rule['description']}: {rule['reason']}"
            )
    
    await db.commit()
    
    # Publish to Kafka
    await publish_transaction_event(
        txn.id, txn.transaction_reference, "transfer_completed",
        current_user.id, from_account.id, to_account.id,
        txn.amount, txn.currency, txn.transaction_type.value,
        txn.status.value, x_forwarded_for, user_agent,
        risk_score, is_suspicious
    )
    
    return txn


@app.post("/transactions/deposit", response_model=TransactionResponse)
async def deposit(
    deposit_data: DepositRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user),
    x_forwarded_for: Optional[str] = Header(None),
    user_agent: Optional[str] = Header(None)
):
    # Only admin can create deposits (simulating bank deposits)
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE]:
        raise HTTPException(status_code=403, detail="Only admins can create deposits")
    
    result = await db.execute(
        select(Account).where(
            Account.id == deposit_data.to_account_id,
            Account.status == AccountStatus.ACTIVE
        )
    )
    to_account = result.scalar_one_or_none()
    if not to_account:
        raise HTTPException(status_code=404, detail="Account not found or inactive")
    
    txn = await create_double_entry_transaction(
        db, None, to_account, deposit_data.amount,
        TransactionType.DEPOSIT, deposit_data.description,
        deposit_data.idempotency_key, x_forwarded_for, user_agent,
        to_account.user_id
    )
    
    await db.commit()
    
    await publish_transaction_event(
        txn.id, txn.transaction_reference, "deposit_completed",
        to_account.user_id, None, to_account.id,
        txn.amount, txn.currency, txn.transaction_type.value,
        txn.status.value, x_forwarded_for, user_agent, 0.0, False
    )
    
    return txn


@app.post("/transactions/withdrawal", response_model=TransactionResponse)
async def withdrawal(
    withdrawal_data: WithdrawalRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user),
    x_forwarded_for: Optional[str] = Header(None),
    user_agent: Optional[str] = Header(None)
):
    from_account = await check_account_ownership(db, withdrawal_data.from_account_id, current_user.id)
    
    if from_account.available_balance < withdrawal_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    
    # Check limits
    if withdrawal_data.amount > from_account.daily_transaction_limit:
        raise HTTPException(status_code=400, detail="Amount exceeds daily transaction limit")
    
    # Fraud detection
    is_suspicious, risk_score, triggered_rules = await evaluate_transaction(
        db, current_user.id, from_account.id, None,
        withdrawal_data.amount, x_forwarded_for, user_agent
    )
    
    txn = await create_double_entry_transaction(
        db, from_account, None, withdrawal_data.amount,
        TransactionType.WITHDRAWAL, withdrawal_data.description,
        withdrawal_data.idempotency_key, x_forwarded_for, user_agent,
        current_user.id
    )
    
    if is_suspicious:
        for rule in triggered_rules:
            await create_fraud_alert(
                db, txn.id, rule['rule'], rule['risk_score'],
                f"{rule['description']}: {rule['reason']}"
            )
    
    await db.commit()
    
    await publish_transaction_event(
        txn.id, txn.transaction_reference, "withdrawal_completed",
        current_user.id, from_account.id, None,
        txn.amount, txn.currency, txn.transaction_type.value,
        txn.status.value, x_forwarded_for, user_agent,
        risk_score, is_suspicious
    )
    
    return txn


@app.get("/transactions", response_model=TransactionHistory)
async def list_transactions(
    account_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    query = select(Transaction).where(
        or_(
            Transaction.from_account_id.in_(
                select(Account.id).where(Account.user_id == current_user.id)
            ),
            Transaction.to_account_id.in_(
                select(Account.id).where(Account.user_id == current_user.id)
            )
        )
    )
    
    if account_id:
        query = query.where(
            or_(
                Transaction.from_account_id == account_id,
                Transaction.to_account_id == account_id
            )
        )
    
    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar()
    
    # Get paginated results
    query = query.order_by(Transaction.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    transactions = result.scalars().all()
    
    return {
        "transactions": transactions,
        "total_count": total,
        "page": page,
        "page_size": page_size
    }


# KYC endpoints
@app.post("/kyc/documents", response_model=KYCDocumentResponse)
async def upload_kyc_document(
    document_type: KYCDocumentType,
    document_number: Optional[str] = None,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    # Validate file
    if file.content_type not in ["image/jpeg", "image/png", "application/pdf"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, or PDF allowed")
    
    # Save file
    file_ext = file.filename.split(".")[-1]
    file_name = f"{current_user.id}_{uuid.uuid4().hex}.{file_ext}"
    file_path = os.path.join(settings.kyc_documents_path, file_name)
    
    content = await file.read()
    if len(content) > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File too large. Max size is {settings.max_file_size_mb}MB")
    
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Create document record
    document = KYCDocument(
        user_id=current_user.id,
        document_type=document_type,
        file_path=file_path,
        document_number=document_number,
        status=KYCStatus.PENDING
    )
    db.add(document)
    await db.flush()
    
    return document


@app.get("/kyc/documents", response_model=List[KYCDocumentResponse])
async def list_kyc_documents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    result = await db.execute(
        select(KYCDocument).where(KYCDocument.user_id == current_user.id)
    )
    return result.scalars().all()


# Statement endpoint
@app.post("/accounts/{account_id}/statement")
async def generate_statement(
    account_id: int,
    start_date: datetime,
    end_date: datetime,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    account = await check_account_ownership(db, account_id, current_user.id)
    
    # Get transactions for period
    result = await db.execute(
        select(Transaction).where(
            or_(
                Transaction.from_account_id == account_id,
                Transaction.to_account_id == account_id
            ),
            Transaction.created_at >= start_date,
            Transaction.created_at <= end_date,
            Transaction.status == TransactionStatus.COMPLETED
        ).order_by(Transaction.created_at)
    )
    transactions = result.scalars().all()
    
    # Generate PDF
    output_file = os.path.join(
        settings.statements_path,
        f"statement_{account.account_number}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.pdf"
    )
    
    await generate_account_statement(
        account, current_user, transactions, start_date, end_date, output_file
    )
    
    return {
        "message": "Statement generated successfully",
        "file_path": output_file,
        "account_number": account.account_number,
        "period": f"{start_date.date()} to {end_date.date()}",
        "transaction_count": len(transactions)
    }


# Admin endpoints
@app.get("/admin/users", response_model=List[UserResponse])
async def admin_list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.execute(select(User))
    return result.scalars().all()


@app.put("/admin/users/{user_id}", response_model=UserResponse)
async def admin_update_user(
    user_id: int,
    update_data: AdminUserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update_data.is_active is not None:
        user.is_active = update_data.is_active
    if update_data.role is not None:
        user.role = update_data.role
    if update_data.email_verified is not None:
        user.email_verified = update_data.email_verified
    
    return user


@app.post("/admin/accounts/{account_id}/freeze")
async def admin_freeze_account(
    account_id: int,
    freeze_data: AccountFreezeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    account.status = AccountStatus.FROZEN
    await db.flush()
    
    return {"message": f"Account {account.account_number} frozen", "reason": freeze_data.reason}


@app.post("/admin/accounts/{account_id}/unfreeze")
async def admin_unfreeze_account(
    account_id: int,
    unfreeze_data: AccountUnfreezeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    if account.status != AccountStatus.FROZEN:
        raise HTTPException(status_code=400, detail="Account is not frozen")
    
    account.status = AccountStatus.ACTIVE
    await db.flush()
    
    return {"message": f"Account {account.account_number} unfrozen", "reason": unfreeze_data.reason}


@app.get("/admin/fraud-alerts", response_model=List[FraudAlertResponse])
async def admin_list_fraud_alerts(
    status: Optional[FraudAlertStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_compliance_access(current_user) and not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Compliance or admin access required")
    
    query = select(FraudAlert)
    if status:
        query = query.where(FraudAlert.status == status)
    
    result = await db.execute(query.order_by(FraudAlert.created_at.desc()))
    return result.scalars().all()


@app.put("/admin/fraud-alerts/{alert_id}", response_model=FraudAlertResponse)
async def admin_review_fraud_alert(
    alert_id: int,
    review_data: FraudAlertReview,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_compliance_access(current_user) and not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Compliance or admin access required")
    
    result = await db.execute(select(FraudAlert).where(FraudAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = review_data.status
    alert.reviewed_by = current_user.id
    alert.reviewed_at = datetime.utcnow()
    alert.resolution_notes = review_data.resolution_notes
    
    return alert


@app.put("/admin/kyc/{document_id}")
async def admin_review_kyc(
    document_id: int,
    status: KYCStatus,
    rejection_reason: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_db_user)
):
    if not check_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await db.execute(select(KYCDocument).where(KYCDocument.id == document_id))
    document = result.scalar_one_or_none()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    document.status = status
    document.verified_by = current_user.id
    document.verified_at = datetime.utcnow()
    if status == KYCStatus.REJECTED:
        document.rejection_reason = rejection_reason
    
    await db.flush()
    
    return {
        "message": f"KYC document {document_id} updated to {status.value}",
        "document_id": document_id,
        "status": status.value
    }
