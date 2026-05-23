from decimal import Decimal
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models import Transaction, Account, FraudAlert, FraudAlertStatus, User
from app.redis_client import (
    record_transaction_attempt,
    get_transaction_velocity,
    record_transaction_amount,
    get_structuring_sum,
)
from app.config import settings


class FraudRule:
    def __init__(self, name: str, description: str, weight: float):
        self.name = name
        self.description = description
        self.weight = weight
    
    async def check(
        self,
        db: AsyncSession,
        user_id: int,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        amount: Decimal,
        ip_address: Optional[str],
        device_info: Optional[str]
    ) -> Tuple[bool, Optional[str], float]:
        """Returns (triggered, reason, risk_score)"""
        raise NotImplementedError


class VelocityRule(FraudRule):
    """Too many transactions in a short time window"""
    
    def __init__(self):
        super().__init__(
            "velocity",
            "High transaction velocity detected",
            0.3
        )
    
    async def check(
        self,
        db: AsyncSession,
        user_id: int,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        amount: Decimal,
        ip_address: Optional[str],
        device_info: Optional[str]
    ) -> Tuple[bool, Optional[str], float]:
        # Record this attempt
        await record_transaction_attempt(user_id, settings.fraud_velocity_window_minutes)
        
        # Check velocity
        count = await get_transaction_velocity(user_id, settings.fraud_velocity_window_minutes)
        
        if count > settings.fraud_velocity_max_transactions:
            risk_score = min(0.9, self.weight + (count - settings.fraud_velocity_max_transactions) * 0.05)
            return True, f"{count} transactions in {settings.fraud_velocity_window_minutes} minutes", risk_score
        
        return False, None, 0.0


class StructuringRule(FraudRule):
    """Multiple transactions just below reporting threshold"""
    
    def __init__(self):
        super().__init__(
            "structuring",
            "Potential structuring activity detected",
            0.4
        )
    
    async def check(
        self,
        db: AsyncSession,
        user_id: int,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        amount: Decimal,
        ip_address: Optional[str],
        device_info: Optional[str]
    ) -> Tuple[bool, Optional[str], float]:
        threshold = Decimal(str(settings.fraud_structuring_threshold))
        
        # Record this transaction
        await record_transaction_amount(
            user_id,
            float(amount),
            settings.fraud_structuring_window_days
        )
        
        # Check for pattern
        count, total = await get_structuring_sum(
            user_id,
            float(threshold),
            settings.fraud_structuring_window_days
        )
        
        if count >= 3 and total >= float(threshold) * 0.8:
            risk_score = min(0.95, self.weight + count * 0.05)
            return True, f"{count} transactions near threshold totaling {total:.2f}", risk_score
        
        return False, None, 0.0


class LargeAmountRule(FraudRule):
    """Unusually large transaction for this user"""
    
    def __init__(self):
        super().__init__(
            "large_amount",
            "Transaction amount significantly above user's average",
            0.25
        )
    
    async def check(
        self,
        db: AsyncSession,
        user_id: int,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        amount: Decimal,
        ip_address: Optional[str],
        device_info: Optional[str]
    ) -> Tuple[bool, Optional[str], float]:
        # Get user's 30-day average transaction amount
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        result = await db.execute(
            select(func.avg(Transaction.amount))
            .where(
                Transaction.created_at >= thirty_days_ago,
                ((Transaction.from_account_id == from_account_id) | 
                 (Transaction.to_account_id == to_account_id))
            )
        )
        avg_amount = result.scalar()
        
        if avg_amount and float(avg_amount) > 0:
            ratio = float(amount) / float(avg_amount)
            if ratio >= 5:  # 5x average
                risk_score = min(0.8, self.weight + (ratio - 5) * 0.02)
                return True, f"Amount {amount} is {ratio:.1f}x user's average", risk_score
        elif float(amount) >= 5000:  # No history, but large amount
            return True, f"Large first-time transaction: {amount}", self.weight
        
        return False, None, 0.0


class GeographicAnomalyRule(FraudRule):
    """Transaction from unusual location (simplified - using IP)"""
    
    def __init__(self):
        super().__init__(
            "geo_anomaly",
            "Transaction from unusual location",
            0.2
        )
    
    async def check(
        self,
        db: AsyncSession,
        user_id: int,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        amount: Decimal,
        ip_address: Optional[str],
        device_info: Optional[str]
    ) -> Tuple[bool, Optional[str], float]:
        # In production, this would geolocate IP and compare to user's history
        # For demo, we'll flag if no IP is present (suspicious) or if it's a new device
        
        if not ip_address:
            return True, "No IP address captured", 0.4
        
        # Check if this is a new device for this user
        if device_info:
            result = await db.execute(
                select(Transaction)
                .where(
                    Transaction.device_info == device_info,
                    ((Transaction.from_account_id == from_account_id) |
                     (Transaction.to_account_id == to_account_id))
                )
                .limit(1)
            )
            existing = result.scalar_one_or_none()
            
            if not existing:
                return True, "New device detected", 0.3
        
        return False, None, 0.0


# Initialize rules
FRAUD_RULES: List[FraudRule] = [
    VelocityRule(),
    StructuringRule(),
    LargeAmountRule(),
    GeographicAnomalyRule(),
]


async def evaluate_transaction(
    db: AsyncSession,
    user_id: int,
    from_account_id: Optional[int],
    to_account_id: Optional[int],
    amount: Decimal,
    ip_address: Optional[str],
    device_info: Optional[str]
) -> Tuple[bool, float, List[Dict]]:
    """
    Evaluate a transaction for fraud.
    Returns: (is_suspicious, total_risk_score, triggered_rules)
    """
    triggered_rules = []
    total_risk_score = 0.0
    
    for rule in FRAUD_RULES:
        triggered, reason, risk_score = await rule.check(
            db, user_id, from_account_id, to_account_id,
            amount, ip_address, device_info
        )
        
        if triggered:
            triggered_rules.append({
                "rule": rule.name,
                "description": rule.description,
                "reason": reason,
                "risk_score": risk_score,
            })
            total_risk_score += risk_score
    
    # Cap risk score at 1.0
    total_risk_score = min(1.0, total_risk_score)
    
    # Suspicious if risk score >= 0.5
    is_suspicious = total_risk_score >= 0.5
    
    return is_suspicious, total_risk_score, triggered_rules


async def create_fraud_alert(
    db: AsyncSession,
    transaction_id: int,
    rule_triggered: str,
    risk_score: float,
    details: str
) -> FraudAlert:
    alert = FraudAlert(
        transaction_id=transaction_id,
        rule_triggered=rule_triggered,
        risk_score=Decimal(str(risk_score)),
        details=details,
        status=FraudAlertStatus.OPEN
    )
    db.add(alert)
    await db.flush()
    return alert
