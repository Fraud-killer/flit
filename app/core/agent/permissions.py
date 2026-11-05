"""
What the agent may do, decided the same way every time.

Rules are strings: a tool name, or a tool name with a subject pattern in
parentheses. `case_resolve` covers every call; `case_resolve(cleared)` covers
clearing; `block_actor(ip:41.58.*)` covers blocks on that range. A `*` in a
pattern matches anything; a pattern without one must match exactly.

Rules come in layers, organization over application over playbook, and they
combine rather than override: every deny from any layer is a deny. The order
is fixed:

    1. a deny rule                        → deny
    2. an ask rule                        → ask
    3. the tool is a read                 → allow
    4. an allow rule                      → allow
    5. the mode: propose → propose, ask → ask, auto → classifier

So an organization that denies `policy_change` has denied it for every
application and every playbook, whatever their allow lists say. Nothing
downstream (the classifier, the hook, the mode) can turn a deny into
anything else. A hook may only tighten; so may the classifier.
"""

import fnmatch
import re

from core.models.agent import AgentMode
from .tools import ToolKind


RULE = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*(?:\((.*)\))?\s*$", re.DOTALL)


class Decision:
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"
    PROPOSE = "propose"

    RANK = {ALLOW: 0, PROPOSE: 1, ASK: 2, DENY: 3}

    def __init__(self, behaviour, *, source, reason=""):
        self.behaviour = behaviour
        self.source = source
        self.reason = reason

    def __repr__(self):
        return f"Decision({self.behaviour}, {self.source})"

    @classmethod
    def tighter(cls, first, second):
        """The more restrictive of two decisions; `first` wins a tie."""
        return second if cls.RANK[second.behaviour] > cls.RANK[first.behaviour] else first


def parse_rule(rule):
    """`tool(pattern)` → (tool, pattern). A malformed rule is a tool-wide rule."""
    match = RULE.match(rule or "")
    if not match:
        return (str(rule or "").strip(), None)
    tool, pattern = match.group(1), match.group(2)
    if pattern is None or pattern.strip() in ("", "*"):
        return (tool, None)
    return (tool, pattern.strip())


def validate_rule_list(rules, known_tools):
    """Problems with a rules list, as strings."""
    problems = []
    if not isinstance(rules, list):
        return ["must be a list of rules"]
    for rule in rules:
        if not isinstance(rule, str) or not rule.strip():
            problems.append(f"{rule!r}: must be a non-empty string")
            continue
        tool, _ = parse_rule(rule)
        if tool not in known_tools:
            problems.append(f"{rule}: unknown tool {tool}")
    return problems


def rule_matches(rule, tool_name, subject):
    tool, pattern = parse_rule(rule)
    if tool != tool_name:
        return False
    if pattern is None:
        return True
    if "*" in pattern:
        return fnmatch.fnmatchcase(subject or "", pattern)
    return (subject or "") == pattern


class Layer:
    """One source of rules: the organization, the application, the playbook."""

    def __init__(self, name, *, allow=(), ask=(), deny=()):
        self.name = name
        self.allow = list(allow or ())
        self.ask = list(ask or ())
        self.deny = list(deny or ())

    def first_match(self, rules, tool_name, subject):
        for rule in rules:
            if rule_matches(rule, tool_name, subject):
                return rule
        return None


class PermissionRules:
    def __init__(self, *layers, mode=AgentMode.PROPOSE):
        self.layers = [layer for layer in layers if layer is not None]
        self.mode = mode

    @classmethod
    def for_run(cls, *, application_policy, organization_policy=None, playbook=None, requested_mode=None):
        """
        Compose the layers for one investigation. The mode is the tightest of
        everything that has a say: the organization's ceiling, the
        application's setting, the playbook's maximum and what was asked for.
        """
        mode = application_policy.mode
        layers = [Layer("application", allow=application_policy.allow, ask=application_policy.ask, deny=application_policy.deny)]

        if organization_policy is not None:
            mode = AgentMode.tighter(mode, organization_policy.mode)
            layers.insert(0, Layer(
                "organization", allow=organization_policy.allow, ask=organization_policy.ask,
                deny=organization_policy.deny,
            ))
        if playbook is not None:
            mode = AgentMode.tighter(mode, playbook.max_mode)
            layers.append(Layer("playbook", deny=getattr(playbook, "deny", ()) or ()))
        if requested_mode:
            mode = AgentMode.tighter(mode, requested_mode)

        return cls(*layers, mode=mode)

    def decide(self, tool, inputs):
        subject = tool.subject(inputs)

        for layer in self.layers:
            rule = layer.first_match(layer.deny, tool.name, subject)
            if rule:
                return Decision(Decision.DENY, source=f"{layer.name}:deny", reason=f"denied by rule {rule}")

        for layer in self.layers:
            rule = layer.first_match(layer.ask, tool.name, subject)
            if rule:
                return Decision(Decision.ASK, source=f"{layer.name}:ask", reason=f"a person must approve: rule {rule}")

        if tool.kind == ToolKind.READ:
            return Decision(Decision.ALLOW, source="read", reason="reads are allowed")

        # An organization's allow does not reach into an application's estate;
        # only the application's own allow list (and the playbook's) can allow a write.
        for layer in self.layers:
            if layer.name == "organization":
                continue
            rule = layer.first_match(layer.allow, tool.name, subject)
            if rule:
                if self.mode == AgentMode.PROPOSE:
                    return Decision(Decision.PROPOSE, source="mode:propose", reason=f"allowed by {rule}, but this run only proposes")
                return Decision(Decision.ALLOW, source=f"{layer.name}:allow", reason=f"allowed by rule {rule}")

        if self.mode == AgentMode.PROPOSE:
            return Decision(Decision.PROPOSE, source="mode:propose", reason="this run only proposes writes")
        if self.mode == AgentMode.ASK:
            return Decision(Decision.ASK, source="mode:ask", reason="writes wait for a person in this mode")
        # AUTO: undecided writes go to the classifier; the loop does that.
        return Decision(Decision.ASK, source="mode:auto", reason="undecided; the classifier will judge it")
