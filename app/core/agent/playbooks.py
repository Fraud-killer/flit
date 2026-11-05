"""
Playbooks: the procedures the agent follows, written by the people who own
the estate.

A playbook is markdown with a frontmatter: a name, a description, what
triggers it, which tools it may use, the most permissive mode it may run in,
a turn limit. The body is the brief. Built-in playbooks ship in this package;
an organization overrides one by saving a playbook of the same name. A
playbook can only narrow what the agent does: it cannot grant a tool the
policy denies, or a mode the policy does not allow.

Before a playbook runs unattended, its proposals are measured against cases
people closed (`evaluate_playbook`), and the result is stored on it.
"""

import re
from pathlib import Path

from core.models.agent import AgentMode, InvestigationTrigger


BUILT_IN_DIR = Path(__file__).parent / "playbooks"
FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)
FIELDS = ("name", "description", "trigger", "tools", "max_mode", "max_turns", "user_invocable")


class PlaybookError(Exception):
    pass


class PlaybookSpec:
    """A parsed playbook, from a file or a row."""

    def __init__(self, *, name, description="", trigger=InvestigationTrigger.MANUAL, tools=(), max_mode=AgentMode.PROPOSE,
                 max_turns=None, body="", user_invocable=True, source="built-in", evaluation=None, enabled=True):
        self.name = name
        self.description = description
        self.trigger = trigger
        self.tools = list(tools or ())
        self.max_mode = max_mode
        self.max_turns = max_turns
        self.body = body
        self.user_invocable = user_invocable
        self.source = source
        self.evaluation = evaluation or {}
        self.enabled = enabled
        # A playbook can deny tools (by leaving them out); it never allows.
        self.deny = ()

    def as_dict(self):
        return dict(
            name=self.name, description=self.description, trigger=self.trigger, tools=self.tools,
            max_mode=self.max_mode, max_turns=self.max_turns, user_invocable=self.user_invocable,
            source=self.source, evaluation=self.evaluation, enabled=self.enabled,
        )

    @classmethod
    def parse(cls, text, *, source="built-in", fallback_name=None):
        """Markdown with a frontmatter → PlaybookSpec. Raises PlaybookError."""
        match = FRONTMATTER.match(text or "")
        if not match:
            raise PlaybookError("a playbook starts with a --- frontmatter ---")
        header, body = match.group(1), match.group(2).strip()
        fields = {}
        for line in header.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if ":" not in line:
                raise PlaybookError(f"frontmatter line without a colon: {line!r}")
            key, value = line.split(":", 1)
            key, value = key.strip().replace("-", "_"), value.strip()
            if key not in FIELDS:
                raise PlaybookError(f"unknown frontmatter field {key}")
            fields[key] = value

        name = fields.get("name") or fallback_name
        if not name or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,79}", name):
            raise PlaybookError("name must be a slug of 2 to 80 characters")
        trigger = fields.get("trigger", InvestigationTrigger.MANUAL)
        if trigger not in InvestigationTrigger.VALUES:
            raise PlaybookError(f"trigger must be one of {InvestigationTrigger.VALUES}")
        max_mode = fields.get("max_mode", AgentMode.PROPOSE)
        if max_mode not in AgentMode.VALUES:
            raise PlaybookError(f"max_mode must be one of {AgentMode.VALUES}")
        tools = [t.strip() for t in re.split(r"[,\s]+", fields.get("tools", "")) if t.strip()]
        tools = [] if tools == ["*"] else tools
        if tools:
            from .tools import Tools
            unknown = sorted(set(tools) - set(Tools.names()))
            if unknown:
                raise PlaybookError(f"unknown tools: {', '.join(unknown)}")
        max_turns = fields.get("max_turns")
        if max_turns is not None:
            if not max_turns.isdigit() or not (1 <= int(max_turns) <= 100):
                raise PlaybookError("max_turns must be 1 to 100")
            max_turns = int(max_turns)
        if not body:
            raise PlaybookError("a playbook needs a body")

        return cls(
            name=name, description=fields.get("description", "")[:300], trigger=trigger, tools=tools,
            max_mode=max_mode, max_turns=max_turns, body=body,
            user_invocable=fields.get("user_invocable", "true").lower() not in ("false", "no", "0"),
            source=source,
        )

    @classmethod
    def from_row(cls, row):
        spec = cls(
            name=row.name, description=row.description, trigger=row.trigger, tools=row.tools or [],
            max_mode=row.max_mode, max_turns=row.max_turns, body=row.body, source="organization",
            evaluation=row.evaluation or {}, enabled=row.enabled,
        )
        return spec


class Playbooks:
    @classmethod
    def built_in(cls):
        specs = {}
        for path in sorted(BUILT_IN_DIR.glob("*.md")):
            spec = PlaybookSpec.parse(path.read_text(encoding="utf-8"), fallback_name=path.stem)
            specs[spec.name] = spec
        return specs

    @classmethod
    def available(cls, organization):
        """Built-ins, overridden by the organization's own, by name."""
        from core.models import Playbook
        specs = cls.built_in()
        for row in Playbook.objects.filter(organization=organization):
            specs[row.name] = PlaybookSpec.from_row(row)
        return specs

    @classmethod
    def resolve(cls, name, organization):
        spec = cls.available(organization).get(name)
        if spec is None:
            raise PlaybookError(f"no playbook named {name}")
        if not spec.enabled:
            raise PlaybookError(f"playbook {name} is disabled")
        return spec

    @classmethod
    def for_trigger(cls, trigger, organization):
        return [spec for spec in cls.available(organization).values() if spec.trigger == trigger and spec.enabled]

    @classmethod
    def save(cls, *, organization, text, created_by=None):
        """Parse and store an organization's playbook. Returns the row."""
        from core.models import Playbook
        spec = PlaybookSpec.parse(text, source="organization")
        row, _ = Playbook.objects.update_or_create(
            organization=organization, name=spec.name,
            defaults=dict(
                description=spec.description, trigger=spec.trigger, tools=spec.tools, max_mode=spec.max_mode,
                max_turns=spec.max_turns, body=spec.body, created_by=created_by,
            ),
        )
        return row

    @classmethod
    def render(cls, spec):
        """The frontmatter and body as one document, for the API."""
        return spec.as_dict() | dict(body=spec.body)
