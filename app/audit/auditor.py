import asyncio
from audit import rules
from audit.scope import Scope
from devkit.struct import Struct


class Auditor:
    rule_classes = (
        rules.AmlCftLimitExceededRule,
        rules.DeviceNotRegisteredRule,
    )

    @classmethod
    async def audit(cls, event, policy):
        # TODO: Ensure the event argument
        # TODO: Ensure the policy argument

        print(event.__dict__)

        scope = Scope(event, policy)

        rules = list()

        for rule_class in cls.rule_classes:
            rule = rule_class(scope)
            if rule.applies: rules.append(rule)

        risk_score = 0.0
        reasons_dict = dict()

        tasks = [rule.execute() for rule in rules]

        for task in asyncio.as_completed(tasks):
            messages = await task
            risk_score += (int(bool(messages)) / len(rules))
            reasons_dict.update((message.code, message) for message in messages) 

        return Struct(risk_score=round(risk_score, 2), reasons=list(reasons_dict.values()))
