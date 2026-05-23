import json
from typing import Optional
from datetime import datetime
from decimal import Decimal
from aiokafka import AIOKafkaProducer
from app.config import settings

producer: Optional[AIOKafkaProducer] = None


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


async def init_kafka():
    global producer
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda v: json.dumps(v, cls=DecimalEncoder).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None,
    )
    await producer.start()


async def close_kafka():
    global producer
    if producer:
        await producer.stop()


async def publish_transaction_event(
    transaction_id: int,
    transaction_reference: str,
    event_type: str,
    user_id: int,
    from_account_id: Optional[int],
    to_account_id: Optional[int],
    amount: Decimal,
    currency: str,
    transaction_type: str,
    status: str,
    ip_address: Optional[str] = None,
    device_info: Optional[str] = None,
    risk_score: Optional[float] = None,
    fraud_alert: bool = False
):
    global producer
    if not producer:
        return
    
    event = {
        "event_id": f"{transaction_reference}_{event_type}_{datetime.utcnow().isoformat()}",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "transaction": {
            "id": transaction_id,
            "reference": transaction_reference,
            "user_id": user_id,
            "from_account_id": from_account_id,
            "to_account_id": to_account_id,
            "amount": str(amount),
            "currency": currency,
            "type": transaction_type,
            "status": status,
        },
        "context": {
            "ip_address": ip_address,
            "device_info": device_info,
        },
        "risk": {
            "score": risk_score,
            "fraud_alert": fraud_alert,
        }
    }
    
    await producer.send(
        settings.kafka_transactions_topic,
        value=event,
        key=str(user_id)
    )
