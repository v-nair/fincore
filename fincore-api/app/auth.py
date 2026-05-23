from datetime import datetime, timedelta
from typing import Optional, Tuple
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import settings
from app.models import User, UserSession, UserRole
from app.schemas import Token

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(user_id: int, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access"
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh"
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None


async def authenticate_user(db: AsyncSession, email: str, password: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.email == email, User.is_active == True))
    user = result.scalar_one_or_none()
    
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def create_user_session(
    db: AsyncSession,
    user_id: int,
    refresh_token: str,
    device_info: Optional[str] = None,
    ip_address: Optional[str] = None
) -> UserSession:
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    
    session = UserSession(
        user_id=user_id,
        refresh_token=refresh_token,
        device_info=device_info,
        ip_address=ip_address,
        expires_at=expires_at
    )
    db.add(session)
    await db.flush()
    return session


async def verify_refresh_token(db: AsyncSession, token: str) -> Optional[User]:
    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        return None
    
    result = await db.execute(
        select(UserSession).where(
            UserSession.refresh_token == token,
            UserSession.revoked == False,
            UserSession.expires_at > datetime.utcnow()
        )
    )
    session = result.scalar_one_or_none()
    
    if not session:
        return None
    
    # Update last login
    result = await db.execute(select(User).where(User.id == session.user_id))
    user = result.scalar_one_or_none()
    if user:
        user.last_login = datetime.utcnow()
    
    return user


async def revoke_refresh_token(db: AsyncSession, token: str) -> bool:
    result = await db.execute(
        select(UserSession).where(UserSession.refresh_token == token)
    )
    session = result.scalar_one_or_none()
    if session:
        session.revoked = True
        return True
    return False


async def revoke_all_user_sessions(db: AsyncSession, user_id: int) -> int:
    result = await db.execute(
        select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked == False
        )
    )
    sessions = result.scalars().all()
    count = 0
    for session in sessions:
        session.revoked = True
        count += 1
    return count


def create_tokens(user_id: int) -> Token:
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


async def get_current_user(db: AsyncSession, token: str) -> Optional[User]:
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None
    
    user_id = int(payload.get("sub"))
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    return result.scalar_one_or_none()


def check_admin_access(user: User) -> bool:
    return user.role in [UserRole.ADMIN, UserRole.COMPLIANCE]


def check_compliance_access(user: User) -> bool:
    return user.role == UserRole.COMPLIANCE
