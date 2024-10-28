import asyncio
from bootkit.struct import Struct
from core.audit.provider import Provider


class Auditor:
    def __init__(self, rule_classes):
        self.rule_classes = rule_classes

    def audit(self, data, policy):
        provider = Provider(data, policy)

        rules = [
            rule_class(data, policy, provider)
            for rule_class in self.rule_classes
        ]

        return asyncio.run(self.execute_rules(rules))

    @classmethod
    async def execute_rules(cls, rules):
        risk_score = 0
        reasons = list()
        
        coroutines = [rule.exert() for rule in rules]

        for coroutine in asyncio.as_completed(coroutines):
            messages = (await coroutine) or list()
            reasons.extend(messages)
            rule_score = 0 if len(messages) == 0 else 1
            risk_score += round(rule_score / len(rules), 2)

        return Struct(risk_score=risk_score, reasons=list(set(reasons)))
