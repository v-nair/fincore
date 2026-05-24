import json
from datetime import datetime
from typing import Optional, Tuple
import redis.asyncio as redis
from app.config import settings

redis_client: Optional[redis.Redis] = None


async def init_redis():
    global redis_client
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.close()


async def get_redis() -> redis.Redis:
    if not redis_client:
        await init_redis()
    return redis_client


# Rate Limiting
async def check_rate_limit(key: str, max_requests: int, window: int) -> Tuple[bool, int]:
    r = await get_redis()
    current = await r.get(key)
    
    if not current:
        await r.setex(key, window, 1)
        return True, max_requests - 1
    
    count = int(current)
    if count >= max_requests:
        ttl = await r.ttl(key)
        return False, ttl
    
    await r.incr(key)
    return True, max_requests - count - 1


# OTP Storage
async def store_otp(key: str, otp: str, expiry: int) -> bool:
    r = await get_redis()
    await r.setex(f"otp:{key}", expiry, otp)
    return True


async def verify_otp(key: str, otp: str) -> bool:
    r = await get_redis()
    stored = await r.get(f"otp:{key}")
    if stored and stored == otp:
        await r.delete(f"otp:{key}")
        return True
    return False


async def increment_otp_attempts(key: str) -> int:
    r = await get_redis()
    attempts_key = f"otp_attempts:{key}"
    attempts = await r.incr(attempts_key)
    if attempts == 1:
        await r.expire(attempts_key, 300)  # 5 minutes
    return attempts


# Transaction Rate Tracking for Fraud Detection
async def record_transaction_attempt(user_id: int, window_minutes: int = 60):
    r = await get_redis()
    key = f"txn_velocity:{user_id}"
    now = int(datetime.utcnow().timestamp())
    
    # Add timestamp to sorted set
    await r.zadd(key, {str(now): now})
    
    # Remove old entries outside window
    cutoff = now - (window_minutes * 60)
    await r.zremrangebyscore(key, 0, cutoff)
    
    # Set expiry on key
    await r.expire(key, window_minutes * 60)


async def get_transaction_velocity(user_id: int, window_minutes: int = 60) -> int:
    r = await get_redis()
    key = f"txn_velocity:{user_id}"
    now = int(datetime.utcnow().timestamp())
    cutoff = now - (window_minutes * 60)
    
    return await r.zcount(key, cutoff, now)


# Structuring Detection (multiple transactions just below threshold)
async def record_transaction_amount(user_id: int, amount: float, window_days: int = 7):
    r = await get_redis()
    key = f"txn_structuring:{user_id}"
    now = int(datetime.utcnow().timestamp())
    
    # Store amount with timestamp
    data = json.dumps({"amount": amount, "timestamp": now})
    await r.zadd(key, {data: now})
    
    # Clean old entries
    cutoff = now - (window_days * 24 * 60 * 60)
    await r.zremrangebyscore(key, 0, cutoff)
    
    # Set expiry
    await r.expire(key, window_days * 24 * 60 * 60)


async def get_structuring_sum(user_id: int, threshold: float, window_days: int = 7) -> Tuple[int, float]:
    r = await get_redis()
    key = f"txn_structuring:{user_id}"
    now = int(datetime.utcnow().timestamp())
    cutoff = now - (window_days * 24 * 60 * 60)
    
    entries = await r.zrangebyscore(key, cutoff, now)
    count = 0
    total = 0.0
    
    for entry in entries:
        data = json.loads(entry)
        amount = data["amount"]
        # Count transactions just below threshold (90% of threshold)
        if amount < threshold and amount >= (threshold * 0.9):
            count += 1
            total += amount
    
    return count, total


# Cache
async def cache_get(key: str) -> Optional[str]:
    r = await get_redis()
    return await r.get(key)


async def cache_set(key: str, value: str, expiry: int = 300):
    r = await get_redis()
    await r.setex(key, expiry, value)


async def cache_delete(key: str):
    r = await get_redis()
    await r.delete(key)


# Session Blacklist (for revoked tokens before expiry)
async def blacklist_token(token_jti: str, expiry_seconds: int):
    r = await get_redis()
    await r.setex(f"blacklist:{token_jti}", expiry_seconds, "1")


async def is_token_blacklisted(token_jti: str) -> bool:
    r = await get_redis()
    return await r.exists(f"blacklist:{token_jti}") > 0
