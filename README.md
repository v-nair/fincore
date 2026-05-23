# FinCore

**Core Banking Platform** — Production-grade banking system demonstrating enterprise architecture patterns for the Toronto fintech market.

## What This Demonstrates

| Pattern | Implementation |
|---------|---------------|
| **Double-entry bookkeeping** | Every transaction creates balanced ledger entries (debit = credit) |
| **ACID compliance** | PostgreSQL serializable transactions for financial data integrity |
| **Fraud detection engine** | Multi-rule scoring: velocity, structuring, large amounts, geo-anomaly |
| **Event sourcing** | Kafka publishes all transactions for downstream audit trails |
| **Rate limiting** | Redis-backed sliding window protection on auth endpoints |
| **KYC workflow** | Document upload → admin review → verification |
| **Role-based access** | Customer, Admin, Compliance role separation |
| **Idempotency** | Transaction deduplication via idempotency keys |

## Quick Start

```bash
cd fincore-api
cp .env.example .env
docker-compose up -d
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## System Architecture

```
Client (React/Mobile)
         │
         ▼
   ┌─────────────┐
   │  FastAPI    │
   │  (Python)   │
   └──────┬──────┘
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
PostgreSQL  Redis  Kafka
  (Ledger) (Cache) (Events)
```

## Key Features

1. **Account Management** - Multiple account types with currency support
2. **Transaction Engine** - Atomic transfers with balance locking
3. **Ledger** - Immutable double-entry records
4. **Fraud Detection** - Real-time risk scoring
5. **Compliance** - KYC verification workflow
6. **Reporting** - PDF statement generation
7. **Admin Controls** - Account freeze, fraud review

## Domain Model

- **User** - Customer with KYC status
- **Account** - Checking/Savings/Investment/Business
- **Transaction** - Transfer/Deposit/Withdrawal with idempotency
- **LedgerEntry** - Double-entry record (debit/credit accounts)
- **FraudAlert** - Suspicious activity flags
- **KYCDocument** - Identity verification documents

## Why This Matters for Banking

Core banking systems require:
- **Consistency over availability** (financial data accuracy)
- **Audit trails** (every action traceable)
- **Compliance** (KYC, AML, fraud detection)
- **Scalability** (handle high transaction volumes)
- **Security** (encryption, rate limiting, session management)

FinCore demonstrates all of these with modern Python async patterns.

## Tech Stack

- Python 3.11 · FastAPI · SQLAlchemy 2.0 (async)
- PostgreSQL 15 · Redis 7 · Kafka
- JWT · OAuth2 · ReportLab (PDF)

## Next Steps

See the API README for detailed endpoints and usage examples.
