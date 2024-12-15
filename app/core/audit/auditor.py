import asyncio
from core.audit import rules
from devkit.struct import Struct
from core.audit.scope import Scope


class Auditor:
    rule_classes = (
        rules.DeviceExpiredRule,
        rules.NewDeviceCountryRule,
        rules.UnregisteredDeviceRule,
        rules.AmlCftLimitExceededRule,
        rules.MaximumSingleDebitExceededRule,
        rules.MaximumSingleCreditExceededRule,
        rules.MaximumCumulativeBalanceExceededRule,
        rules.MaximumDailyCumulativeDebitExceededRule,
    )

    @classmethod
    async def audit(cls, event, policy):
        # TODO: Ensure arguments

        rules = list()
        scope = Scope()

        for rule_class in cls.rule_classes:
            rule = rule_class(event=event, policy=policy, scope=scope)
            if rule.applies: rules.append(rule)

        risk_score = 0
        reasons = list()

        rule_tasks = [rule.execute(False) for rule in rules]

        for rule_task in asyncio.as_completed(rule_tasks):
            messages = await rule_task

            reasons.extend(messages)
            rule_risk_weight = int(bool(messages))
            risk_score += (rule_risk_weight / len(rules))

        risk_score = round(float(risk_score), 2)
        rule_names = [rule.__class__.__name__ for rule in rules]

        return Struct(risk_score=risk_score, rules=rule_names, reasons=reasons)
