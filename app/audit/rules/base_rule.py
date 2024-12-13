from asyncio import gather
from audit.scope import ScopeError
from devkit.message import Message
from abc import ABCMeta, abstractmethod


class RuleError(Exception):
    pass


class BaseRule(metaclass=ABCMeta):
    requires = list()

    def __init__(self, scope):
        self.scope = scope

    @property
    @abstractmethod
    def applies(self):
        pass

    @abstractmethod
    async def perform(self):
        pass

    async def execute(self, registry=dict()):
        class_name = self.__class__.__name__

        if not self.applies:
            error_message = "Not applicable to the scope"
            raise RuleError(f"{class_name}: {error_message}")

        tasks = list()

        for rule_class in self.requires:
            if rule_class in registry:
                task = registry[rule_class]
                tasks.append(task)
                continue

            rule_name = rule_class.__name__
            error_message = f"{rule_name} not in registry"
            raise RuleError(f"{class_name}: {error_message}")

        skip_perform = any(result for result in await gather(*tasks))

        try:
            result = (
                list()
                if skip_perform
                else await self.perform()
            )
        except ScopeError as error: result = error.args[0]

        if result is None: return list()
        if isinstance(result, Message): return [result]

        if isinstance(result, list) and not any(
            not isinstance(item, Message) for item in result
        ):
            return result

        raise RuleError(f"{class_name}: Execute method result is invalid")
