"""
The one place the agent talks to the model.

Every call goes through `ModelClient`, so tests can script it, costs are
counted in one place, and the failure modes are named: a rate limit, an API
error, a connection error, a refusal, an answer cut off. None of them is an
answer; the caller decides what "unavailable" means for it.
"""

import json
import hashlib
import logging

from kernel.config import Config


logger = logging.getLogger(__name__)


class ModelUnavailable(Exception):
    pass


class ModelRefused(ModelUnavailable):
    pass


class ModelClient:
    """A thin wrapper over the Anthropic SDK; `make()` is what tests replace."""

    @classmethod
    def model(cls, override=None):
        return override or getattr(Config, "agent_model", None) or "claude-opus-5-5"

    @classmethod
    def verifier_model(cls):
        return getattr(Config, "agent_verifier_model", None) or cls.model()

    @classmethod
    def make(cls):
        try:
            import anthropic
        except ImportError as error:
            raise ModelUnavailable("the anthropic package is not installed") from error
        return anthropic.Anthropic()

    @classmethod
    def create(cls, client, **kwargs):
        """One request. Translates the SDK's errors into ModelUnavailable."""
        try:
            import anthropic
        except ImportError as error:
            raise ModelUnavailable("the anthropic package is not installed") from error

        try:
            return client.messages.create(**kwargs)
        except anthropic.RateLimitError as error:
            raise ModelUnavailable(f"rate limited ({error.status_code})") from error
        except anthropic.APIStatusError as error:
            raise ModelUnavailable(f"api error {error.status_code}") from error
        except anthropic.APIConnectionError as error:
            raise ModelUnavailable("connection error") from error

    @classmethod
    def structured(cls, client, *, model, system, user, schema, effort="medium", max_tokens=2000):
        """
        One question, one JSON answer that fits `schema`. Anything else raises.
        The system prompt is cached; the question is not.
        """
        response = cls.create(
            client,
            model=model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
            messages=[{"role": "user", "content": user}],
        )
        cls.check_stop(response)
        text = next((block.text for block in response.content if getattr(block, "type", None) == "text"), None)
        if not text:
            raise ModelUnavailable("no text in answer")
        try:
            answer = json.loads(text)
        except ValueError as error:
            raise ModelUnavailable("answer was not JSON") from error

        from .tools import validate_against
        problems = validate_against(schema, answer, path="answer")
        if problems:
            raise ModelUnavailable("answer did not fit the schema: " + "; ".join(problems[:3]))
        return answer, response

    @staticmethod
    def check_stop(response):
        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None)
            raise ModelRefused(f"refused ({category or 'unspecified'})")
        if response.stop_reason == "max_tokens":
            raise ModelUnavailable("answer was cut off")


def prompt_version(*parts):
    """A short digest of the prompt text in force, written on every run."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update((part or "").encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]


def block_to_dict(block):
    """An SDK content block (or a test stand-in) as the dict the API accepts back."""
    if isinstance(block, dict):
        return block
    if hasattr(block, "model_dump"):
        return block.model_dump(exclude_none=True)
    data = {k: v for k, v in vars(block).items() if not k.startswith("_") and v is not None}
    return data
