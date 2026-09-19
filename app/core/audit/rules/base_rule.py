from devkit.struct import Struct
from devkit.message import Message
from devkit.checks import is_present
from abc import ABCMeta, abstractmethod

from core.taxonomy import Maturity


class RuleKind:
    """What a rule is for, which decides how it appears in coverage."""

    # Detects a fraud technique. Counts towards F3 coverage.
    DETECTION = "detection"

    # Enforces a policy limit the merchant set (AML ceilings, per-transaction
    # maxima). Always "fires" by design when the limit is crossed, so it is
    # not evidence of fraud and is not scored as coverage.
    CONTROL = "control"

    # Evidence about the actor rather than about a technique — network
    # corroboration, a failed challenge. Applies across every technique, so
    # attributing it to one would be arbitrary.
    CORROBORATION = "corroboration"

    VALUES = (DETECTION, CONTROL, CORROBORATION)


class RuleError(Exception):
    pass


class RulePresentError(RuleError):
    pass


class BaseRule(metaclass=ABCMeta):
    """
    A single piece of reasoning about an event.

    Beyond the logic, every rule declares what it is for and how much it has
    actually been shown to work. Those declarations are not documentation:
    they are read by core.taxonomy to generate the coverage matrix, and a
    rule that claims more evidence than it has will fail the test suite.
    """

    # Which MITRE F3 techniques this rule detects, by identifier. FLIT maps
    # onto the industry's taxonomy rather than inventing one — see
    # core.taxonomy.f3 for why.
    techniques = ()

    # What kind of rule this is. Not everything detects a technique: a limit
    # enforces policy, and a reputation lookup is evidence about the actor
    # rather than about what they are doing.
    kind = RuleKind.DETECTION

    # Where this rule sits on the evidence ladder, and what put it there.
    # PROPOSED is the honest default and is not a criticism — it means the
    # rule is reasoned rather than measured.
    maturity = Maturity.PROPOSED
    provenance = ""

    # From `backtested` upward the claim is numerical, so it has to name the
    # rule codes whose measurements support it. Those codes must exist in the
    # evidence ledger or the test suite rejects the claim.
    evidence_codes = ()

    def __init__(self, *, event, scope, policy):
        self.event = event
        self.scope = scope
        self.policy = policy
        self.application=policy.application

    @property
    @abstractmethod
    def applies(self):
        pass

    @abstractmethod
    async def perform(self):
        pass

    def normalize(self, mapping):
        name = mapping[type(self.event)]
        value = getattr(self.event, name)
        return Struct(name=name, value=value)

    def ensure_present(self, mapping):
        absents = [
            name for name, value in mapping.items()
            if not is_present(value)
        ]

        if absents: raise RulePresentError(absents)

    async def execute(self, check_applies=True):
        class_name = self.__class__.__name__

        if check_applies and not self.applies:
            error_message = "Not applicable to the scope"
            raise RuleError(f"{class_name}: {error_message}")

        try:
            result = await self.perform()
        except RulePresentError as error:
            return [
                Message(
                    code="req_event_attrs",
                    context=dict(
                        rule=class_name,
                        attributes=list(error.args[0]),
                    ),
                    text="Some event attributes are required and cannot be null",
                )
            ]

        if result is None: result = list()
        if isinstance(result, Message): result = [result]

        if not isinstance(result, list) or any(
            not isinstance(item, Message) for item in result
        ):
            raise RuleError(f"{class_name}: Perform result is invalid")

        return [msg.new(context=dict(rule=class_name, **msg.context)) for msg in result]
