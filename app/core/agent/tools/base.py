"""
The contract a tool meets to be offered to the agent.

A tool is a named, schema-checked function over FLIT's own services. It
declares whether it reads or writes, and it names its *subject*: the one
string a permission rule can match (`block_actor(ip:41.58.*)`,
`case_resolve(cleared)`). Writes also describe themselves in a sentence, the
sentence a person reads when asked to approve.

Everything a tool returns is data to the model, and the model is told so.
Tool outputs are sanitised before they leave: no user agent strings, no email
addresses, no gateway text, no raw payloads. Those are the channels an
attacker controls; a model that reads them can be talked to. Identity goes
in as shape (`client_class`) or as a redacted form.
"""

import json
import hashlib


class ToolKind:
    READ = "read"
    WRITE = "write"


class ToolError(Exception):
    """A tool could not do what was asked. The message is shown to the model."""


class ToolContext:
    """What a tool needs besides its inputs: whose estate, which run, who asked."""

    def __init__(self, *, application, investigation=None, actor=None, now=None):
        from django.utils import timezone

        self.application = application
        self.investigation = investigation
        self.actor = actor
        self.now = now or timezone.now()

    @property
    def organization(self):
        return self.application.organization


class Tool:
    name = ""
    description = ""
    kind = ToolKind.READ
    input_schema = {"type": "object", "properties": {}, "additionalProperties": False}
    # A write that changes the engine's policy or closes a case is reviewed
    # by an independent reader before it may run unattended.
    needs_verification = False
    # Terminal tools end the investigation when called.
    terminal = False

    @classmethod
    def subject(cls, inputs):
        """The string permission rules match against. Empty for tool-wide only."""
        return ""

    @classmethod
    def describe(cls, inputs):
        """One sentence for the person asked to approve this call."""
        return f"{cls.name} {json.dumps(inputs, sort_keys=True, default=str)}"

    @classmethod
    def run(cls, inputs, context):
        raise NotImplementedError

    @classmethod
    def definition(cls):
        return dict(name=cls.name, description=cls.description, input_schema=cls.input_schema)

    @classmethod
    def validate(cls, inputs):
        """Errors in `inputs` against the schema, as strings. Cheap, not a full validator."""
        return validate_against(cls.input_schema, inputs, path=cls.name)


def validate_against(schema, value, path=""):
    """
    A small JSON-schema checker: types, required, enum, additionalProperties,
    minimum/maximum, minLength/maxLength, items. Enough to refuse an input
    that the model shaped wrongly before it reaches a service.
    """
    errors = []
    kind = schema.get("type")
    types = {
        "object": dict, "array": list, "string": str, "integer": int,
        "number": (int, float), "boolean": bool, "null": type(None),
    }
    if kind and kind in types:
        expected = types[kind]
        if isinstance(value, bool) and kind in ("integer", "number"):
            errors.append(f"{path}: expected {kind}")
            return errors
        if not isinstance(value, expected):
            errors.append(f"{path}: expected {kind}")
            return errors
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: too long")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, dict) and kind == "object":
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: unknown field")
        for key, sub in properties.items():
            if key in value:
                errors.extend(validate_against(sub, value[key], f"{path}.{key}"))
    if isinstance(value, list) and kind == "array":
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(validate_against(item_schema, item, f"{path}[{index}]"))
    return errors


# Keys whose values a user typed or an upstream system echoed. They never
# reach the model. `email` is replaced by its redacted form where a tool wants
# to keep the shape; everything else is dropped.
DROP_KEYS = frozenset({
    "user_agent", "gateway_message", "error_message", "raw_data", "headers",
    "email", "name", "first_name", "last_name", "phone", "phone_number",
    "address", "description_text", "memo", "narration", "note", "notes", "body",
    "resolution_note", "secret_key", "webhook_secret", "collect_key",
})
MAX_STRING = 300
MAX_ITEMS = 60


def sanitize(value, *, depth=0):
    """Drop the free-text channels, cap sizes, make everything JSON-safe."""
    if depth > 12:
        return "…"
    if isinstance(value, dict):
        return {
            str(key): sanitize(item, depth=depth + 1)
            for key, item in value.items()
            if str(key) not in DROP_KEYS
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        out = [sanitize(item, depth=depth + 1) for item in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            out.append(f"… {len(items) - MAX_ITEMS} more")
        return out
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING else value[:MAX_STRING] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def digest(value):
    encoded = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), len(encoded)


def client_class(user_agent):
    from core.intelligence.bot_detection import BotDetector
    return BotDetector.client_class(user_agent)


def redact_email(value):
    if not value:
        return None
    from core.intelligence.email_intelligence import redact
    return redact(value)


def iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value
