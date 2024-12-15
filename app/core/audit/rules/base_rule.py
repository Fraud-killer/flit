from devkit.struct import Struct
from devkit.message import Message
from devkit.checks import is_present
from abc import ABCMeta, abstractmethod


class RuleError(Exception):
    pass


class RulePresentError(RuleError):
    pass


class BaseRule(metaclass=ABCMeta):
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
