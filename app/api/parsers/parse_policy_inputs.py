from devkit import undefined
from devkit.struct import Struct
from devkit.messages import msg_dict, msg_void_or_decimal

from core.decision import validate_rules
from core.messages.policies import msg_weights_empty, msg_outbound_url
from core.models.challenge import ChallengeMethod
from core.outbound import BlockedAddressError, check_url
from core.outbound.webhooks import EVENTS as WEBHOOK_EVENTS
from devkit.messages import msg_in_choices

from .parse_application_id import parse_application_id
from .parse_simulation_inputs import is_ratio, is_weight_map


THRESHOLD_KEYS = {"block_at", "review_at", "challenge_at"}
MIN_LATENCY_BUDGET_MS = 50
MAX_LATENCY_BUDGET_MS = 30000


def parse_policy_inputs(id, request):
    errors = list()
    application = parse_application_id(id, errors)
    changes = dict()

    if request.method == "PATCH":
        body = request.data if isinstance(request.data, dict) else {}

        thresholds = body.get("thresholds", undefined)
        if thresholds is not undefined:
            if not (isinstance(thresholds, dict) and set(thresholds).issubset(THRESHOLD_KEYS)
                    and all(is_ratio(v) for v in thresholds.values())):
                errors.append(msg_dict.new(path="thresholds", context=dict(keys=sorted(THRESHOLD_KEYS))))
            else:
                changes["thresholds"] = {k: float(v) for k, v in thresholds.items()}

        weights = body.get("weights", undefined)
        if weights is not undefined:
            if not is_weight_map(weights):
                errors.append(msg_dict.new(path="weights", context=dict(values="numbers between 0 and 1")))
            elif not weights or all(float(v) == 0 for v in weights.values()):
                # An empty or all-zero weight set is a poisoned policy, not a reset.
                errors.append(msg_weights_empty)
            else:
                changes["weights"] = {k: float(v) for k, v in weights.items()}

        rules = body.get("rules", undefined)
        if rules is not undefined:
            problems = validate_rules(rules)
            if problems:
                errors.extend(problems)
            else:
                changes["rules"] = rules

        disabled = body.get("disabled_rules", undefined)
        if disabled is not undefined:
            if not (isinstance(disabled, list) and all(isinstance(name, str) and name for name in disabled)):
                errors.append(msg_dict.new(path="disabled_rules", context=dict(values="rule class names")))
            else:
                changes["disabled_rules"] = sorted(set(disabled))

        shadow = body.get("shadow_rules", undefined)
        if shadow is not undefined:
            if not (isinstance(shadow, list) and all(isinstance(name, str) and name for name in shadow)):
                errors.append(msg_dict.new(path="shadow_rules", context=dict(values="rule class names")))
            else:
                changes["shadow_rules"] = sorted(set(shadow))

        method = body.get("challenge_method", undefined)
        if method is not undefined:
            if method is not None and method not in ChallengeMethod.VALUES:
                errors.append(msg_in_choices.new(
                    path="challenge_method", context=dict(choices=ChallengeMethod.VALUES + [None]),
                ))
            else:
                changes["challenge_method"] = method

        webhook = body.get("webhook", undefined)
        if webhook is not undefined:
            if webhook is None:
                changes["webhook"] = None
            elif not isinstance(webhook, dict):
                errors.append(msg_dict.new(path="webhook", context=dict(keys=["url", "secret", "events"])))
            else:
                problems = validate_webhook(webhook)
                if problems:
                    errors.extend(problems)
                else:
                    changes["webhook"] = webhook

        hook = body.get("decision_hook", undefined)
        if hook is not undefined:
            if hook is None:
                changes["decision_hook"] = None
            elif not isinstance(hook, dict):
                errors.append(msg_dict.new(path="decision_hook", context=dict(keys=["url", "timeout_ms"])))
            else:
                problems = validate_decision_hook(hook)
                if problems:
                    errors.extend(problems)
                else:
                    changes["decision_hook"] = hook

        budget = body.get("latency_budget_ms", undefined)
        if budget is not undefined:
            if not (isinstance(budget, int) and not isinstance(budget, bool)
                    and MIN_LATENCY_BUDGET_MS <= budget <= MAX_LATENCY_BUDGET_MS):
                errors.append(msg_void_or_decimal.new(
                    path="latency_budget_ms",
                    context=dict(minimum=MIN_LATENCY_BUDGET_MS, maximum=MAX_LATENCY_BUDGET_MS),
                ))
            else:
                changes["latency_budget_ms"] = budget

    data = None if errors else Struct(application=application, changes=changes)

    return (data, errors)


def validate_outbound_url(url, path):
    if not isinstance(url, str) or not url.strip():
        return [msg_outbound_url.new(path=path)]
    try:
        check_url(url.strip())
    except BlockedAddressError as error:
        return [msg_outbound_url.new(path=path, context=dict(detail=str(error)))]
    return []


def validate_webhook(webhook):
    errors = validate_outbound_url(webhook.get("url"), "webhook.url")
    secret = webhook.get("secret")
    if secret is not None and (not isinstance(secret, str) or len(secret) < 16):
        errors.append(msg_dict.new(path="webhook.secret", context=dict(values="a string of at least 16 characters")))
    events = webhook.get("events")
    if events is not None and not (
        isinstance(events, list) and set(events).issubset(WEBHOOK_EVENTS)
    ):
        errors.append(msg_in_choices.new(path="webhook.events", context=dict(choices=list(WEBHOOK_EVENTS))))
    return errors


def validate_decision_hook(hook):
    errors = validate_outbound_url(hook.get("url"), "decision_hook.url")
    timeout = hook.get("timeout_ms")
    if timeout is not None and not (isinstance(timeout, int) and not isinstance(timeout, bool) and 50 <= timeout <= 2000):
        errors.append(msg_void_or_decimal.new(path="decision_hook.timeout_ms", context=dict(minimum=50, maximum=2000)))
    return errors
