"""
Measuring a playbook before it runs unattended.

The ground truth FLIT has is the cases people closed. An evaluation replays a
playbook over a sample of them in propose mode, with the case's status hidden
from the model (it reads the case as open), and compares the report's verdict
with what the person decided. Agreement is what the auto-mode gate reads: a
playbook that has not agreed with people at least MIN_AGREEMENT of the time
over MIN_N decided cases proposes or asks, whatever the mode says.
"""

import logging

from django.utils import timezone

from core.models import AgentPolicy, Case, CaseStatus, InvestigationStatus, InvestigationTrigger, AgentMode, Playbook


logger = logging.getLogger(__name__)


class PlaybookEval:
    MIN_AGREEMENT = 0.9
    MIN_N = 20
    VERDICT_FOR = {CaseStatus.CONFIRMED_FRAUD: "confirmed_fraud", CaseStatus.CLEARED: "cleared"}

    @classmethod
    def sample(cls, application, size):
        """
        Cases a person closed, newest first. A case the agent closed, or that
        a person closed by approving the agent's own verdict, is not ground
        truth about the agent and is left out; otherwise the agent would be
        graded against itself once auto mode is on.
        """
        from core.models import Investigation, StepStatus

        agent_closed = (
            Investigation.objects.filter(
                application=application, case__isnull=False,
                steps__tool="case_resolve", steps__status__in=(StepStatus.EXECUTED, StepStatus.APPROVED),
            ).values_list("case_id", flat=True)
        )
        return list(
            Case.objects.filter(application=application)
            .exclude(status=CaseStatus.OPEN)
            .exclude(triage_auto_closed=True)
            .exclude(id__in=agent_closed)
            .select_related("audit_log")
            .order_by("-closed_at")[:size]
        )

    @classmethod
    def run(cls, *, application, playbook, size=20, client=None):
        from .loop import Investigations, InvestigationRunner

        cases = cls.sample(application, size)
        agreed = disagreed = deferred = failed = 0
        cost = 0.0
        rows = []

        for case in cases:
            investigation = Investigations.open(
                application=application, playbook=playbook, case=case, trigger=InvestigationTrigger.EVALUATION,
                mode=AgentMode.PROPOSE, subject=dict(evaluation=True),
            )
            investigation = InvestigationRunner.start(investigation, client=client)
            cost += investigation.cost_usd
            expected = cls.VERDICT_FOR.get(case.status)
            verdict = (investigation.report or {}).get("verdict") if investigation.status == InvestigationStatus.COMPLETED else None
            if verdict is None:
                failed += 1
                outcome = "failed"
            elif verdict in ("confirmed_fraud", "cleared"):
                if verdict == expected:
                    agreed += 1
                    outcome = "agreed"
                else:
                    disagreed += 1
                    outcome = "disagreed"
            else:
                deferred += 1
                outcome = "deferred"
            rows.append(dict(case_id=str(case.id), human=case.status, agent=verdict, outcome=outcome))

        decided = agreed + disagreed
        result = dict(
            playbook=playbook, n=len(cases), decided=decided, agreed=agreed, disagreed=disagreed,
            deferred=deferred, failed=failed,
            agreement=round(agreed / decided, 4) if decided else None,
            coverage=round(decided / len(cases), 4) if cases else None,
            cost_usd=round(cost, 4), evaluated_at=timezone.now().isoformat(), cases=rows,
        )
        cls.store(application, playbook, result)
        return result

    @classmethod
    def store(cls, application, playbook, result):
        stored = {k: v for k, v in result.items() if k != "cases"}
        policy = AgentPolicy.for_application(application)
        evaluations = dict(policy.evaluations or {})
        evaluations[playbook] = stored
        policy.evaluations = evaluations
        policy.save(update_fields=["evaluations", "updated_at"])
        row = Playbook.objects.filter(organization=application.organization, name=playbook).first()
        if row is not None:
            row.evaluation = stored
            row.save(update_fields=["evaluation", "updated_at"])

    @classmethod
    def may_run_unattended(cls, policy, playbook):
        """Has this playbook earned auto mode on this application?"""
        result = (policy.evaluations or {}).get(playbook) or {}
        agreement = result.get("agreement")
        return (
            agreement is not None
            and result.get("decided", 0) >= cls.MIN_N
            and agreement >= cls.MIN_AGREEMENT
        )

    @classmethod
    def ceiling(cls, policy, playbook, mode):
        """The mode after the evaluation gate: auto needs a measured playbook."""
        if mode == AgentMode.AUTO and not cls.may_run_unattended(policy, playbook):
            return AgentMode.ASK
        return mode
