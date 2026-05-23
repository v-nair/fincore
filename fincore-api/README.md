# FinCore API

Production-grade core banking platform with double-entry bookkeeping, fraud detection, and event streaming.

## Features

- **Multi-tenant account management**: Checking, Savings, Investment, Business accounts
- **Double-entry ledger**: Every transaction has matching debit/credit entries
- **Real-time fraud detection**: Velocity, structuring, large amount, and geographic anomaly rules
- **KYC document management**: Upload, verification workflow, admin review
- **Rate limiting & session management**: Redis-backed OTP storage and token blacklisting
- **Event streaming**: Kafka producer publishes all transactions for downstream consumers
- **PDF statement generation**: ReportLab-powered account statements
- **Admin & compliance portals**: Account freeze/unfreeze, fraud alert review, KYC verification

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI Application                   │
├─────────────────────────────────────────────────────────┤
│  Auth (OAuth2/JWT)  │  Accounts  │  Transactions        │
│  - Register/Login   │  - CRUD    │  - Double-entry      │
│  - Refresh tokens   │  - Balance │  - Fraud check       │
│  - MFA (future)     │  - Limits  │  - Kafka publish     │
├─────────────────────────────────────────────────────────┤
│  KYC Documents      │  Admin     │  Statements          │
│  - Upload/Verify    │  - Freeze  │  - PDF Generation    │
│                     │  - Fraud   │                      │
└─────────────────────────────────────────────────────────┘
        │              │              │
    PostgreSQL      Redis          Kafka
  (ACID ledger)  (Rate limit)  (Event stream)
```

## Quick Start

```bash
# Environment
cp .env.example .env
# Edit .env with your settings

# Docker Compose (includes PostgreSQL, Redis, Kafka)
docker-compose up -d

# Local development
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - Login with rate limiting
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Revoke session
- `POST /auth/logout-all` - Revoke all sessions

### Accounts
- `POST /accounts` - Create account (requires KYC)
- `GET /accounts` - List user accounts
- `GET /accounts/{id}` - Account details
- `GET /accounts/{id}/balance` - Current balance
- `POST /accounts/{id}/statement` - Generate PDF statement

### Transactions
- `POST /transactions/transfer` - Account-to-account transfer
- `POST /transactions/deposit` - Admin deposit (simulated)
- `POST /transactions/withdrawal` - Cash withdrawal
- `GET /transactions` - Transaction history

### KYC
- `POST /kyc/documents` - Upload KYC document
- `GET /kyc/documents` - List user documents

### Admin
- `GET /admin/users` - List all users
- `PUT /admin/users/{id}` - Update user (freeze, role change)
- `POST /admin/accounts/{id}/freeze` - Freeze account
- `POST /admin/accounts/{id}/unfreeze` - Unfreeze account
- `GET /admin/fraud-alerts` - List fraud alerts
- `PUT /admin/fraud-alerts/{id}` - Review alert
- `PUT /admin/kyc/{id}` - Approve/Reject KYC

## Fraud Detection Rules

| Rule | Trigger | Risk Score |
|------|---------|------------|
| Velocity | >10 transactions in 60 min | 0.3 + |
| Structuring | 3+ transactions near $10K threshold | 0.4 + |
| Large Amount | 5x user's average or >$5K first txn | 0.25 + |
| Geographic | New device or missing IP | 0.2 - 0.4 |

## Tech Stack

- **FastAPI** - Async web framework
- **SQLAlchemy 2.0** - Async ORM with PostgreSQL
- **Alembic** - Database migrations
- **Redis** - Rate limiting, OTP, session cache
- **Kafka** - Event streaming
- **ReportLab** - PDF generation
- **python-jose** - JWT handling

## Environment Variables

```env
DATABASE_URL=postgresql+asyncpg://fincore:fincore@localhost:5432/fincore
REDIS_URL=redis://localhost:6379/0
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
SECRET_KEY=your-secret-key-min-32-chars
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

## License

MIT
