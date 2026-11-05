def serialize_case(case):
    audit_log = case.audit_log
    context = audit_log.context or {}

    return dict(
        id=str(case.id),
        status=case.status,
        priority=case.priority,
        campaign_key=case.campaign_key,
        decision_count=case.decision_count,
        last_decision_at=case.last_decision_at,
        triage=None if not case.triage_proposal else dict(
            verdict=case.triage_proposal.get("verdict"),
            confidence=case.triage_proposal.get("confidence"),
            reason=case.triage_proposal.get("reason"),
            summary=case.triage_proposal.get("summary"),
            unavailable=case.triage_proposal.get("unavailable"),
            proposed_at=case.triage_at,
            auto_closed=case.triage_auto_closed,
        ),
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
