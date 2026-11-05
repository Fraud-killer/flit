def serialize_investigation(investigation, *, steps=False, transcript=False):
    data = dict(
        id=str(investigation.id),
        playbook=investigation.playbook,
        trigger=investigation.trigger,
        subject=investigation.subject,
        mode=investigation.mode,
        status=investigation.status,
        case_id=str(investigation.case_id) if investigation.case_id else None,
        requested_by=getattr(investigation.requested_by, "email", None),
        model=investigation.model,
        prompt_version=investigation.prompt_version,
        turns=investigation.turns,
        compactions=investigation.compactions,
        cost_usd=round(investigation.cost_usd, 4),
        usage=investigation.usage,
        summary=investigation.summary,
        report=investigation.report,
        error=investigation.error or None,
        created_at=investigation.created_at,
        started_at=investigation.started_at,
        finished_at=investigation.finished_at,
    )
    if steps:
        data["steps"] = [serialize_step(step) for step in investigation.steps.order_by("index")]
        data["pending_steps"] = [s["id"] for s in data["steps"] if s["status"] == "pending"]
    if transcript:
        data["transcript"] = investigation.transcript
    return data


def serialize_step(step):
    return dict(
        id=str(step.id),
        index=step.index,
        kind=step.kind,
        tool=step.tool or None,
        subject=step.subject or None,
        inputs=step.inputs,
        decision=step.decision or None,
        decision_source=step.decision_source or None,
        decision_reason=step.decision_reason or None,
        hook=step.hook,
        verifier=step.verifier,
        status=step.status,
        output=step.output,
        output_sha256=step.output_sha256 or None,
        output_chars=step.output_chars,
        error=step.error or None,
        resolved_by=getattr(step.resolved_by, "email", None),
        resolution_note=step.resolution_note or None,
        resolved_at=step.resolved_at,
        audit_log_id=str(step.audit_log_id) if step.audit_log_id else None,
        created_at=step.created_at,
    )


def serialize_memory(memory):
    from core.agent.memory import Memory
    return dict(
        id=str(memory.id),
        name=memory.name,
        kind=memory.kind,
        description=memory.description,
        body=memory.body,
        tags=memory.tags,
        refers_to=memory.refers_to,
        provenance=memory.provenance,
        application_id=str(memory.application_id) if memory.application_id else None,
        confirmed=memory.is_confirmed,
        confirmed_at=memory.confirmed_at,
        confirmed_by=getattr(memory.confirmed_by, "email", None),
        created_by=getattr(memory.created_by, "email", None),
        expires_at=memory.expires_at,
        active=memory.active,
        recalled_count=memory.recalled_count,
        last_recalled_at=memory.last_recalled_at,
        stale=Memory.stale_reasons(memory),
        created_at=memory.created_at,
        updated_at=memory.updated_at,
    )


def serialize_monitor(monitor):
    return dict(
        id=str(monitor.id),
        name=monitor.name,
        subject=monitor.subject,
        metric=monitor.metric,
        factor=monitor.factor or None,
        threshold=monitor.threshold,
        window_minutes=monitor.window_minutes,
        action=monitor.action,
        playbook=monitor.playbook or None,
        status=monitor.status,
        expires_at=monitor.expires_at,
        fired_at=monitor.fired_at,
        fired_value=monitor.fired_value,
        investigation_id=str(monitor.investigation_id) if monitor.investigation_id else None,
        source_investigation_id=str(monitor.source_investigation_id) if monitor.source_investigation_id else None,
        created_by=getattr(monitor.created_by, "email", None),
        created_at=monitor.created_at,
    )
