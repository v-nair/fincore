from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://fincore:fincore@localhost:5432/fincore"
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_transactions_topic: str = "transactions"
    
    # Security
    secret_key: str = "your-secret-key-here-min-32-characters-long"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    
    # OTP
    otp_expiry_seconds: int = 300
    max_otp_attempts: int = 3
    
    # Fraud Detection
    fraud_velocity_window_minutes: int = 60
    fraud_velocity_max_transactions: int = 10
    fraud_structuring_threshold: float = 10000.00
    fraud_structuring_window_days: int = 7
    
    # File Storage
    kyc_documents_path: str = "./kyc_documents"
    statements_path: str = "./statements"
    max_file_size_mb: int = 10
    
    # Environment
    environment: str = "development"
    debug: bool = False
    
    # Pagination
    default_page_size: int = 20
    max_page_size: int = 100
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
