"""
Agent FLIT: the analyst's agent on top of the decision engine.

The agent investigates, explains, proposes, monitors and reports. The engine
remains the only thing that enforces. Everything the agent does is a row here
and a line on the audit chain, so a security team can read back what it saw,
what it was allowed to do, what it asked for and what a person decided.
"""

from uuid import uuid4

from django.db import models
from django.utils import timezone

from .user import User
from .case import Case
from .application import Application
from .organization import Organization


class AgentMode:
    """
    How much the agent may do on its own.

    propose: writes are recorded as proposals and never executed.
    ask:     each write waits for a person, unless an allow rule covers it.
    auto:    writes a classifier judges safe run on their own; the rest ask.
    """
    PROPOSE = "propose"
    ASK = "ask"
    AUTO = "auto"

    CHOICES = [(PROPOSE, "Propose only"), (ASK, "Ask before writing"), (AUTO, "Auto")]
    VALUES = [value for value, _ in CHOICES]
    # Higher is more permissive. An organization's mode is a ceiling.
    RANK = {PROPOSE: 0, ASK: 1, AUTO: 2}

    @classmethod
    def tighter(cls, first, second):
        return first if cls.RANK[first] <= cls.RANK[second] else second


class AgentPolicy(models.Model):
    """
    What the agent may do for one application, or the ceiling an organization
    sets over all of its applications. Exactly one of the two is set.

    Rules use the same shape as a permission list: a tool name, or a tool name
    with a subject pattern in parentheses, `case_resolve(cleared)` or
    `block_actor(ip:41.58.*)`. Deny beats ask beats allow, across every layer.
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.OneToOneField(
        Application, null=True, blank=True, on_delete=models.CASCADE, related_name="agent_policy",
    )
    organization = models.OneToOneField(
        Organization, null=True, blank=True, on_delete=models.CASCADE, related_name="agent_policy",
    )

    enabled = models.BooleanField(default=True)
    mode = models.CharField(max_length=10, choices=AgentMode.CHOICES, default=AgentMode.PROPOSE)

    allow = models.JSONField(default=list, blank=True)
    ask = models.JSONField(default=list, blank=True)
    deny = models.JSONField(default=list, blank=True)

    # Plain-language standing instructions the auto-mode classifier judges a
    # write against. Never shown to the investigating model as instructions
    # from a user; it is the operator's policy.
    auto_rules = models.TextField(blank=True, default="")

    # A URL the bank controls, consulted before and after every tool call and
    # when an investigation stops. It may only tighten.
    hook_url = models.URLField(max_length=500, null=True, blank=True)
    hook_timeout_ms = models.IntegerField(default=2000)

    max_cost_usd = models.FloatField(default=2.0)
    daily_budget_usd = models.FloatField(default=50.0)
    max_turns = models.IntegerField(default=24)
    model = models.CharField(max_length=80, null=True, blank=True)

    # Open an investigation for every case the engine opens, under the
    # playbooks whose trigger is case_opened. Off until a team asks for it.
    investigate_cases = models.BooleanField(default=False)
    # How each playbook's proposals agreed with the cases people closed, by
    # playbook name: {"investigate_case": {"agreement": 0.93, "n": 40, ...}}.
    # A playbook runs unattended only once this says it may.
    evaluations = models.JSONField(default=dict, blank=True)

    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(application__isnull=False, organization__isnull=True)
                    | models.Q(application__isnull=True, organization__isnull=False)
                ),
                name="agent_policy_one_owner",
            ),
        ]

    def __str__(self):
        owner = self.application or self.organization
        return f"AgentPolicy({owner})"

    @classmethod
    def for_application(cls, application):
        policy, _ = cls.objects.get_or_create(application=application)
        return policy

    @classmethod
    def for_organization(cls, organization):
        return cls.objects.filter(organization=organization).first()


class InvestigationStatus:
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    CHOICES = [
        (QUEUED, "Queued"), (RUNNING, "Running"), (AWAITING_APPROVAL, "Awaiting approval"),
        (COMPLETED, "Completed"), (FAILED, "Failed"), (CANCELLED, "Cancelled"),
    ]
    VALUES = [value for value, _ in CHOICES]
    OPEN = (QUEUED, RUNNING, AWAITING_APPROVAL)


class InvestigationTrigger:
    MANUAL = "manual"
    CASE_OPENED = "case_opened"
    MONITOR = "monitor"
    SCHEDULE = "schedule"
    EVALUATION = "evaluation"

    CHOICES = [
        (MANUAL, "Manual"), (CASE_OPENED, "Case opened"), (MONITOR, "Monitor"),
        (SCHEDULE, "Schedule"), (EVALUATION, "Evaluation"),
    ]
    VALUES = [value for value, _ in CHOICES]


class Investigation(models.Model):
    """
    One run of the agent: a playbook, a subject, the conversation it had with
    its tools, and the report it ended with. The transcript is kept so a run
    can pause for a person and resume, and so it can be read back later.
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="investigations")
    case = models.ForeignKey(Case, null=True, blank=True, on_delete=models.SET_NULL, related_name="investigations")

    playbook = models.CharField(max_length=80)
    trigger = models.CharField(max_length=20, choices=InvestigationTrigger.CHOICES, default=InvestigationTrigger.MANUAL)
    # What the run is about: {"client_id": ..., "device_id": ..., "ip_address": ..., "case_id": ...}
    subject = models.JSONField(default=dict, blank=True)
    # The mode this run is held to: the tightest of organization, application,
    # playbook and whatever the person asked for.
    mode = models.CharField(max_length=10, choices=AgentMode.CHOICES, default=AgentMode.PROPOSE)
    status = models.CharField(max_length=20, choices=InvestigationStatus.CHOICES, default=InvestigationStatus.QUEUED, db_index=True)

    requested_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    model = models.CharField(max_length=80, blank=True, default="")
    prompt_version = models.CharField(max_length=64, blank=True, default="")

    transcript = models.JSONField(default=list, blank=True)
    report = models.JSONField(null=True, blank=True)
    summary = models.TextField(blank=True, default="")
    error = models.TextField(blank=True, default="")

    usage = models.JSONField(default=dict, blank=True)
    cost_usd = models.FloatField(default=0.0)
    turns = models.IntegerField(default=0)
    compactions = models.IntegerField(default=0)
    denials = models.IntegerField(default=0)

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Investigation({self.playbook}, {self.status})"

    @property
    def is_open(self):
        return self.status in InvestigationStatus.OPEN

    def finish(self, status, *, error=""):
        self.status = status
        self.error = error or ""
        self.finished_at = timezone.now()
        self.save(update_fields=["status", "error", "finished_at", "updated_at"])
        return self


class StepKind:
    TOOL = "tool"
    COMPACTION = "compaction"
    REPORT = "report"
    NOTE = "note"

    CHOICES = [(TOOL, "Tool call"), (COMPACTION, "Compaction"), (REPORT, "Report"), (NOTE, "Note")]


class StepStatus:
    EXECUTED = "executed"
    PROPOSED = "proposed"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DENIED = "denied"
    FAILED = "failed"

    CHOICES = [
        (EXECUTED, "Executed"), (PROPOSED, "Proposed"), (PENDING, "Pending approval"),
        (APPROVED, "Approved"), (REJECTED, "Rejected"), (DENIED, "Denied"), (FAILED, "Failed"),
    ]
    VALUES = [value for value, _ in CHOICES]


class InvestigationStep(models.Model):
    """
    One thing the agent did or tried to do. For a tool call: the inputs, the
    permission decision and where it came from, what the bank's hook said,
    what the verifier said, and the output (capped; the digest of the whole
    is kept so the preview can be checked against a record elsewhere).
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name="steps")
    index = models.IntegerField()
    kind = models.CharField(max_length=12, choices=StepKind.CHOICES, default=StepKind.TOOL)

    tool = models.CharField(max_length=60, blank=True, default="")
    tool_use_id = models.CharField(max_length=80, blank=True, default="")
    inputs = models.JSONField(default=dict, blank=True)
    subject = models.CharField(max_length=300, blank=True, default="")

    decision = models.CharField(max_length=10, blank=True, default="")     # allow | ask | deny | propose
    decision_source = models.CharField(max_length=60, blank=True, default="")
    decision_reason = models.TextField(blank=True, default="")
    hook = models.JSONField(null=True, blank=True)
    verifier = models.JSONField(null=True, blank=True)

    status = models.CharField(max_length=12, choices=StepStatus.CHOICES, default=StepStatus.EXECUTED, db_index=True)
    output = models.JSONField(null=True, blank=True)
    output_sha256 = models.CharField(max_length=64, blank=True, default="")
    output_chars = models.IntegerField(default=0)
    error = models.TextField(blank=True, default="")

    resolved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    resolution_note = models.TextField(blank=True, default="")
    resolved_at = models.DateTimeField(null=True, blank=True)

    audit_log_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["index"]
        unique_together = [("investigation", "index")]

    def __str__(self):
        return f"Step({self.index}, {self.tool or self.kind}, {self.status})"


class MemoryKind:
    FACT = "fact"            # something true about this estate: a trusted partner, a known office IP
    FEEDBACK = "feedback"    # an analyst's correction: "rule X is noisy for us, because ..."
    CAMPAIGN = "campaign"    # an attack seen here: its shape, origins, what stopped it
    REFERENCE = "reference"  # a pointer: a ticket, a runbook, a regulator's letter

    CHOICES = [(FACT, "Fact"), (FEEDBACK, "Feedback"), (CAMPAIGN, "Campaign"), (REFERENCE, "Reference")]
    VALUES = [value for value, _ in CHOICES]


class AgentMemory(models.Model):
    """
    One fact the agent may recall later. Memories belong to an organization
    and optionally to one of its applications. A memory the agent wrote for
    itself is unconfirmed until a person confirms it, and is recalled with
    that marker; an attacker who can make the agent remember something must
    not be able to make it believe it.
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="agent_memories")
    application = models.ForeignKey(Application, null=True, blank=True, on_delete=models.CASCADE, related_name="agent_memories")

    kind = models.CharField(max_length=12, choices=MemoryKind.CHOICES, default=MemoryKind.FACT)
    name = models.SlugField(max_length=80)
    description = models.CharField(max_length=200)
    body = models.TextField()
    tags = models.JSONField(default=list, blank=True)
    # What the memory is about, so recall can check it still exists:
    # {"rule": "VelocityCheckRule", "client_id": "...", "ip_address": "...", "factor": "..."}
    refers_to = models.JSONField(default=dict, blank=True)
    # {"kind": "analyst"|"agent", "user_id": ..., "investigation_id": ...}
    provenance = models.JSONField(default=dict, blank=True)

    confirmed_at = models.DateTimeField(null=True, blank=True)
    confirmed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    expires_at = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    recalled_count = models.IntegerField(default=0)
    last_recalled_at = models.DateTimeField(null=True, blank=True)

    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("organization", "name")]
        ordering = ["-updated_at"]

    def __str__(self):
        return f"Memory({self.name})"

    @property
    def is_confirmed(self):
        return self.confirmed_at is not None

    @property
    def age_days(self):
        return (timezone.now() - self.updated_at).days


class MonitorStatus:
    ACTIVE = "active"
    FIRED = "fired"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    CHOICES = [(ACTIVE, "Active"), (FIRED, "Fired"), (EXPIRED, "Expired"), (CANCELLED, "Cancelled")]
    VALUES = [value for value, _ in CHOICES]


class MonitorMetric:
    BLOCK_STREAK = "block_streak"      # consecutive blocks for an origin (device or ip)
    DECISIONS = "decisions"            # decisions for the subject in the window
    BLOCKS = "blocks"                  # blocked decisions for the subject in the window
    FACTOR = "factor"                  # decisions carrying a factor code in the window
    OPEN_CASES = "open_cases"          # open cases for the subject

    CHOICES = [
        (BLOCK_STREAK, "Block streak"), (DECISIONS, "Decisions"), (BLOCKS, "Blocks"),
        (FACTOR, "Factor seen"), (OPEN_CASES, "Open cases"),
    ]
    VALUES = [value for value, _ in CHOICES]


class MonitorAction:
    ALERT = "alert"
    INVESTIGATE = "investigate"

    CHOICES = [(ALERT, "Alert"), (INVESTIGATE, "Alert and investigate")]
    VALUES = [value for value, _ in CHOICES]


class Monitor(models.Model):
    """
    "Wake me when." A condition over one subject, checked on a schedule. When
    it fires it alerts, and may queue an investigation under a playbook.
    Monitors expire; a watch nobody renews is not a watch.
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="monitors")
    name = models.CharField(max_length=120)
    # {"client_id": ...} | {"device_id": ...} | {"ip_address": ...} | {} for the whole application
    subject = models.JSONField(default=dict, blank=True)
    metric = models.CharField(max_length=20, choices=MonitorMetric.CHOICES)
    factor = models.CharField(max_length=80, blank=True, default="")
    threshold = models.IntegerField()
    window_minutes = models.IntegerField(default=60)
    action = models.CharField(max_length=12, choices=MonitorAction.CHOICES, default=MonitorAction.ALERT)
    playbook = models.CharField(max_length=80, blank=True, default="")

    status = models.CharField(max_length=10, choices=MonitorStatus.CHOICES, default=MonitorStatus.ACTIVE, db_index=True)
    expires_at = models.DateTimeField()
    fired_at = models.DateTimeField(null=True, blank=True)
    fired_value = models.IntegerField(null=True, blank=True)
    investigation = models.ForeignKey(Investigation, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    source_investigation = models.ForeignKey(Investigation, null=True, blank=True, on_delete=models.SET_NULL, related_name="monitors_opened")

    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Monitor({self.name}, {self.status})"


class Playbook(models.Model):
    """
    A procedure the agent follows, written by the security team as markdown
    with a frontmatter: which tools it may use, the most permissive mode it
    may run in, what triggers it. A playbook overrides the built-in of the
    same name for its organization. A playbook may run in auto mode only once
    its proposals have been measured against cases people closed.
    """
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="playbooks")
    name = models.SlugField(max_length=80)
    description = models.CharField(max_length=300, blank=True, default="")
    trigger = models.CharField(max_length=20, choices=InvestigationTrigger.CHOICES, default=InvestigationTrigger.MANUAL)
    tools = models.JSONField(default=list, blank=True)       # [] means every tool
    max_mode = models.CharField(max_length=10, choices=AgentMode.CHOICES, default=AgentMode.PROPOSE)
    max_turns = models.IntegerField(null=True, blank=True)
    body = models.TextField()
    enabled = models.BooleanField(default=True)
    # {"agreement": 0.93, "n": 40, "evaluated_at": ..., "by_verdict": {...}}
    evaluation = models.JSONField(default=dict, blank=True)

    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("organization", "name")]
        ordering = ["name"]

    def __str__(self):
        return f"Playbook({self.name})"
