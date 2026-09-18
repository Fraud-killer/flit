def serialize_case(case):
    audit_log = case.audit_log
    context = audit_log.context or {}

    return dict(
        id=str(case.id),
        status=case.status,
        opened_at=case.opened_at,
        closed_at=case.closed_at,
        resolution_note=case.resolution_note,
        assignee=getattr(case.assignee, "email", None),
        audit_id=str(audit_log.id),
        event_id=audit_log.resource_id,
        client_id=audit_log.actor_id,
        device_id=context.get("device_id"),
        risk_score=audit_log.risk_score,
        risk_level=context.get("risk_level"),
        factors=audit_log.risk_factors,
        label=audit_log.label,
    )
