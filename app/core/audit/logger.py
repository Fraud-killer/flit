import logging
from typing import Any, Dict, List, Optional
from uuid import UUID
from django.utils import timezone
from django.db import transaction

from core.audit.models import AuditLog, AuditLogLevel, AuditLogCategory


logger = logging.getLogger(__name__)


class AuditLogger:
    @classmethod
    def _get_last_hash(cls, application_id: Optional[UUID] = None) -> Optional[str]:
        queryset = AuditLog.objects.order_by("-timestamp")
        if application_id:
            queryset = queryset.filter(application_id=application_id)
        
        last_entry = queryset.first()
        return last_entry.entry_hash if last_entry else None

    @classmethod
    def log(
        cls,
        level: str,
        category: str,
        action: str,
        *,
        actor_type: Optional[str] = None,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        application_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        request_id: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        risk_score: Optional[float] = None,
        risk_factors: Optional[List[str]] = None,
        outcome: Optional[str] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> AuditLog:
        with transaction.atomic():
            previous_hash = cls._get_last_hash(application_id)

            entry = AuditLog(
                timestamp=timezone.now(),
                level=level,
                category=category,
                action=action,
                actor_type=actor_type,
                actor_id=str(actor_id) if actor_id else None,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                application_id=application_id,
                organization_id=organization_id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                request_id=request_id,
                request_method=request_method,
                request_path=request_path,
                context=context or {},
                risk_score=risk_score,
                risk_factors=risk_factors or [],
                outcome=outcome,
                error_code=error_code,
                error_message=error_message,
                previous_hash=previous_hash,
            )
            entry.save()

            return entry

    @classmethod
    def log_authentication(
        cls,
        action: str,
        *,
        success: bool,
        actor_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        application_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> AuditLog:
        return cls.log(
            level=AuditLogLevel.INFO if success else AuditLogLevel.WARNING,
            category=AuditLogCategory.AUTHENTICATION,
            action=action,
            actor_type="user",
            actor_id=actor_id,
            application_id=application_id,
            ip_address=ip_address,
            user_agent=user_agent,
            context=context,
            outcome="success" if success else "failure",
            error_message=error_message,
        )

    @classmethod
    def log_authorization(
        cls,
        action: str,
        *,
        allowed: bool,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        application_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        return cls.log(
            level=AuditLogLevel.INFO if allowed else AuditLogLevel.WARNING,
            category=AuditLogCategory.AUTHORIZATION,
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            application_id=application_id,
            context=context,
            outcome="allowed" if allowed else "denied",
        )

    @classmethod
    def log_transaction(
        cls,
        action: str,
        *,
        actor_id: str,
        application_id: UUID,
        amount: Optional[str] = None,
        currency: Optional[str] = None,
        risk_score: Optional[float] = None,
        risk_factors: Optional[List[str]] = None,
        outcome: str,
        context: Optional[Dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        tx_context = context or {}
        if amount:
            tx_context["amount"] = amount
        if currency:
            tx_context["currency"] = currency

        return cls.log(
            level=AuditLogLevel.INFO if risk_score is None or risk_score < 0.5 else AuditLogLevel.WARNING,
            category=AuditLogCategory.TRANSACTION,
            action=action,
            actor_type="user",
            actor_id=actor_id,
            application_id=application_id,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            context=tx_context,
            risk_score=risk_score,
            risk_factors=risk_factors,
            outcome=outcome,
        )

    @classmethod
    def log_device(
        cls,
        action: str,
        *,
        device_id: str,
        device_fingerprint: str,
        application_id: UUID,
        actor_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        outcome: str = "success",
    ) -> AuditLog:
        return cls.log(
            level=AuditLogLevel.INFO,
            category=AuditLogCategory.DEVICE,
            action=action,
            actor_type="user" if actor_id else None,
            actor_id=actor_id,
            resource_type="device",
            resource_id=device_id,
            application_id=application_id,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            context=context,
            outcome=outcome,
        )

    @classmethod
    def log_security_event(
        cls,
        action: str,
        *,
        level: str = AuditLogLevel.WARNING,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        application_id: Optional[UUID] = None,
        context: Optional[Dict[str, Any]] = None,
        risk_score: Optional[float] = None,
        risk_factors: Optional[List[str]] = None,
    ) -> AuditLog:
        return cls.log(
            level=level,
            category=AuditLogCategory.SECURITY,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            application_id=application_id,
            context=context,
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    @classmethod
    def verify_chain_integrity(
        cls,
        application_id: Optional[UUID] = None,
        start_date: Optional[timezone.datetime] = None,
        end_date: Optional[timezone.datetime] = None,
    ) -> Dict[str, Any]:
        queryset = AuditLog.objects.order_by("timestamp")

        if application_id:
            queryset = queryset.filter(application_id=application_id)
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)

        entries = list(queryset)
        total = len(entries)
        valid = 0
        invalid_entries = []

        for i, entry in enumerate(entries):
            if entry.verify_integrity():
                valid += 1
            else:
                invalid_entries.append({
                    "id": str(entry.id),
                    "timestamp": entry.timestamp.isoformat(),
                    "action": entry.action,
                })

            if i > 0:
                if entry.previous_hash != entries[i - 1].entry_hash:
                    invalid_entries.append({
                        "id": str(entry.id),
                        "timestamp": entry.timestamp.isoformat(),
                        "issue": "chain_break",
                    })

        return {
            "total_entries": total,
            "valid_entries": valid,
            "invalid_entries": invalid_entries,
            "chain_valid": len(invalid_entries) == 0,
        }
