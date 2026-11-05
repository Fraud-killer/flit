"""
Decisions a person has already made, applied before the arithmetic.

A score weighs evidence. Some things are not evidence to be weighed: this
address is blocked, that partner's accounts are never challenged, anyone
from this ASN gets a step-up. A fraud team needs to say those things in
plain terms and have them hold regardless of what the weights happen to
think today.

Four actions, in the order they win:

    block > review > challenge > allow

A block is a hard block: it does not care about a clean history or a lenient
calibration. An allow is the weakest thing here on purpose. It suppresses
the review and challenge a *score* would have produced; it never overrides
a block, and it never silences a control that did not run. A merchant can
make FLIT stricter from the console. Making it blind takes more than a list.

Rules are typed, not strings. Each names a subject — what it matches on —
and a pattern that subject knows how to read. A subject validates its own
pattern when the rule is written, and a rule whose subject cannot be read
off the event simply does not fire: an unevaluable condition is not a match.

Two layers: the organization's rules, which every application under it
inherits and cannot remove, and the application's own.
"""

import fnmatch
import ipaddress
from datetime import datetime, timezone as dt_timezone

from devkit.message import Message


ACTIONS = ("block", "review", "challenge", "allow")

# Subject -> (validator, matcher). A validator returns an error string or
# None; a matcher takes (pattern, facts) and returns a bool.
SUBJECTS = {}


def subject(name):
    def register(matcher_class):
        SUBJECTS[name] = matcher_class
        matcher_class.name = name
        return matcher_class
    return register


class Matcher:
    name = None

    @staticmethod
    def validate(pattern):
        if not isinstance(pattern, str) or not pattern.strip():
            return "pattern must be a non-empty string"
        return None

    @staticmethod
    def matches(pattern, facts):
        raise NotImplementedError


@subject("ip")
class IpMatcher(Matcher):
    @staticmethod
    def validate(pattern):
        try:
            ipaddress.ip_address(str(pattern).strip())
        except ValueError:
            return "pattern must be an IP address"
        return None

    @staticmethod
    def matches(pattern, facts):
        ip = facts.get("ip")
        if ip is None:
            return False
        try:
            return ipaddress.ip_address(str(ip)) == ipaddress.ip_address(str(pattern).strip())
        except ValueError:
            return False


@subject("cidr")
class CidrMatcher(Matcher):
    @staticmethod
    def validate(pattern):
        try:
            ipaddress.ip_network(str(pattern).strip(), strict=False)
        except ValueError:
            return "pattern must be a CIDR range"
        return None

    @staticmethod
    def matches(pattern, facts):
        ip = facts.get("ip")
        if ip is None:
            return False
        try:
            return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(pattern).strip(), strict=False)
        except ValueError:
            return False


@subject("country")
class CountryMatcher(Matcher):
    @staticmethod
    def validate(pattern):
        if not isinstance(pattern, str) or len(pattern.strip()) != 2 or not pattern.strip().isalpha():
            return "pattern must be a two-letter country code"
        return None

    @staticmethod
    def matches(pattern, facts):
        country = facts.get("country")
        return bool(country) and str(country).strip().upper() == pattern.strip().upper()


@subject("asn")
class AsnMatcher(Matcher):
    @staticmethod
    def validate(pattern):
        try:
            int(str(pattern).strip().upper().removeprefix("AS"))
        except ValueError:
            return "pattern must be an AS number"
        return None

    @staticmethod
    def matches(pattern, facts):
        asn = facts.get("asn")
        if asn is None:
            return False
        try:
            return int(str(asn).strip().upper().removeprefix("AS")) == int(
                str(pattern).strip().upper().removeprefix("AS")
            )
        except ValueError:
            return False


@subject("email_root")
class EmailRootMatcher(Matcher):
    @staticmethod
    def validate(pattern):
        if not isinstance(pattern, str) or "@" not in pattern:
            return "pattern must be an email address"
        return None

    @staticmethod
    def matches(pattern, facts):
        from core.intelligence.email_intelligence import normalize_email

        root = facts.get("email_root")
        return bool(root) and root == normalize_email(pattern)


@subject("email_domain")
class EmailDomainMatcher(Matcher):
    """`example.com` is that domain; `*.example.com` is it and anything under it."""

    @staticmethod
    def validate(pattern):
        if not isinstance(pattern, str) or "." not in pattern or "@" in pattern or " " in pattern:
            return "pattern must be a domain, optionally starting with *."
        return None

    @staticmethod
    def matches(pattern, facts):
        domain = (facts.get("email_domain") or "").lower().strip(".")
        if not domain:
            return False
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern


@subject("device")
class DeviceMatcher(Matcher):
    @staticmethod
    def matches(pattern, facts):
        pattern = pattern.strip()
        return pattern in {str(value) for value in facts.get("devices") or [] if value}


@subject("client_id")
class ClientIdMatcher(Matcher):
    """Exact, or a glob: `partner-*` covers every account that partner created."""

    @staticmethod
    def matches(pattern, facts):
        client_id = facts.get("client_id")
        return bool(client_id) and fnmatch.fnmatchcase(str(client_id), pattern.strip())


@subject("wallet")
class WalletMatcher(Matcher):
    @staticmethod
    def matches(pattern, facts):
        from core.intelligence.wallet_intelligence import address_key

        wallet = facts.get("wallet")
        if not wallet:
            return False
        chain = facts.get("chain")
        return wallet == address_key(pattern.strip(), chain) or wallet == pattern.strip()


@subject("counterparty")
class CounterpartyMatcher(Matcher):
    """A counterparty id the merchant uses, or a destination wallet address."""

    @staticmethod
    def matches(pattern, facts):
        from core.intelligence.wallet_intelligence import address_key

        pattern = pattern.strip()
        candidates = {str(value) for value in facts.get("counterparties") or [] if value}
        if pattern in candidates:
            return True
        try:
            return address_key(pattern, facts.get("chain")) in candidates
        except Exception:
            return False


@subject("factor")
class FactorMatcher(Matcher):
    """A rule code this decision produced, or a glob over codes."""

    @staticmethod
    def matches(pattern, facts):
        pattern = pattern.strip()
        return any(fnmatch.fnmatchcase(code, pattern) for code in facts.get("factors") or [])


# Subjects that need the rules to have run first.
POST_SCORING_SUBJECTS = {"factor"}


def normalize_rules(rules):
    """Every action present, each a list."""
    rules = rules if isinstance(rules, dict) else {}
    return {action: list(rules.get(action) or []) for action in ACTIONS}


def validate_rules(rules):
    """
    Errors in a rules payload, as Messages with a path into it.

    Shape: {"block": [{"subject": ..., "pattern": ..., "reason"?, "expires_at"?}], ...}
    """
    errors = []

    if not isinstance(rules, dict):
        return [Message(code="dict", text="Rules must be an object keyed by action", path="rules")]

    unknown = set(rules) - set(ACTIONS)
    if unknown:
        errors.append(Message(
            code="in_choices", path="rules",
            text=f"Unknown action(s): {', '.join(sorted(unknown))}",
            context=dict(choices=list(ACTIONS)),
        ))

    for action in ACTIONS:
        entries = rules.get(action)
        if entries is None:
            continue
        if not isinstance(entries, list):
            errors.append(Message(code="list", text="Must be a list of rules", path=f"rules.{action}"))
            continue
        for index, entry in enumerate(entries):
            path = f"rules.{action}[{index}]"
            if not isinstance(entry, dict):
                errors.append(Message(code="dict", text="A rule is an object", path=path))
                continue
            name = entry.get("subject")
            matcher = SUBJECTS.get(name)
            if matcher is None:
                errors.append(Message(
                    code="in_choices", path=f"{path}.subject",
                    text=f"Unknown subject: {name}",
                    context=dict(choices=sorted(SUBJECTS)),
                ))
                continue
            problem = matcher.validate(entry.get("pattern"))
            if problem:
                errors.append(Message(code="pattern", text=problem, path=f"{path}.pattern"))
            expires = entry.get("expires_at")
            if expires is not None and _parse_when(expires) is None:
                errors.append(Message(code="datetime", text="Must be an ISO 8601 datetime", path=f"{path}.expires_at"))
            reason = entry.get("reason")
            if reason is not None and not isinstance(reason, str):
                errors.append(Message(code="trimmed_string", text="Must be a string", path=f"{path}.reason"))

    return errors


def _parse_when(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt_timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt_timezone.utc)


class DecisionRules:
    """The rules in force for one application: its organization's, then its own."""

    def __init__(self, *layers):
        # [(layer_name, normalized rules)]
        self.layers = [(name, normalize_rules(rules)) for name, rules in layers if rules]

    @classmethod
    def for_policy(cls, policy, organization_policy=None):
        return cls(
            ("organization", getattr(organization_policy, "rules", None)),
            ("application", getattr(policy, "rules", None)),
        )

    def __bool__(self):
        return any(entries for _, rules in self.layers for entries in rules.values())

    def matches(self, facts, *, now=None, phase="all"):
        """
        Which rules fire on these facts: {action: [match, ...]}.

        `phase` is "pre" for subjects readable before the rules run, "post"
        for those that need the rule codes, or "all".
        """
        now = now or datetime.now(dt_timezone.utc)
        found = {action: [] for action in ACTIONS}

        for layer, rules in self.layers:
            for action in ACTIONS:
                for entry in rules[action]:
                    name = entry.get("subject")
                    matcher = SUBJECTS.get(name)
                    if matcher is None:
                        continue
                    if phase == "pre" and name in POST_SCORING_SUBJECTS:
                        continue
                    if phase == "post" and name not in POST_SCORING_SUBJECTS:
                        continue
                    expires = _parse_when(entry.get("expires_at")) if entry.get("expires_at") else None
                    if expires is not None and expires <= now:
                        continue
                    try:
                        hit = matcher.matches(str(entry.get("pattern")), facts)
                    except Exception:
                        # A condition that cannot be evaluated is not a match.
                        hit = False
                    if hit:
                        found[action].append(dict(
                            layer=layer, subject=name, pattern=entry.get("pattern"),
                            reason=entry.get("reason"),
                        ))

        return found

    @staticmethod
    def facts(event, scope=None, visit=None, factors=None):
        """What the matchers can read off one event."""
        from core.intelligence.email_intelligence import normalize_email
        from core.intelligence import wallet_intelligence

        def value(name):
            from devkit.checks import is_present
            raw = getattr(event, name, None)
            if not is_present(raw):
                raw = (getattr(event, "extra", None) or {}).get(name)
            return raw if is_present(raw) else None

        ladder = getattr(scope, "identity_ladder", None) if scope else None
        device = getattr(scope, "device_identity", None) if scope else None

        def rung(key_type):
            found = ladder.get(key_type) if ladder else None
            return found.value if found else None

        email = value("email")
        email_root = None
        email_domain = None
        if email and "@" in str(email):
            try:
                email_root = normalize_email(str(email))
            except Exception:
                email_root = str(email).lower()
            email_domain = str(email).rsplit("@", 1)[1].lower()

        chain = value("chain")
        wallet_address = value("wallet_address")
        wallet = None
        if wallet_address:
            try:
                wallet = wallet_intelligence.address_key(wallet_address, chain)
            except Exception:
                wallet = str(wallet_address)

        counterparties = [value("counterparty_id")]
        counterparty_address = value("counterparty_address")
        if counterparty_address:
            counterparties.append(counterparty_address)
            try:
                counterparties.append(wallet_intelligence.address_key(counterparty_address, chain))
            except Exception:
                pass

        country = value("country")
        if not country and visit is not None:
            country = getattr(visit, "country_code", None) or None

        asn = getattr(visit, "asn", None) if visit is not None else None
        if asn is None:
            asn = rung("asn")

        return dict(
            ip=value("ip_address") or (getattr(visit, "ip", None) if visit is not None else None),
            country=country,
            asn=asn,
            email_root=email_root or rung("email_root"),
            email_domain=email_domain,
            devices=[
                getattr(device, "id", None), getattr(device, "external_id", None), rung("device"),
            ],
            client_id=getattr(event, "account_id", None),
            wallet=wallet or rung("wallet"),
            chain=chain,
            counterparties=[c for c in counterparties if c],
            factors=list(factors or []),
        )

    @staticmethod
    def messages(matches):
        """The findings a set of matches adds to the decision."""
        messages = []

        if matches.get("block"):
            messages.append(Message(
                code="policy_block",
                path=matches["block"][0]["subject"],
                text="Blocked by policy: " + _describe(matches["block"]),
                context=dict(severity=1.0, hard_block=True, matched=matches["block"]),
            ))
        if matches.get("review"):
            messages.append(Message(
                code="policy_review",
                path=matches["review"][0]["subject"],
                text="Sent to review by policy: " + _describe(matches["review"]),
                context=dict(score=0.0, force_review=True, matched=matches["review"]),
            ))
        if matches.get("challenge"):
            messages.append(Message(
                code="policy_challenge",
                path=matches["challenge"][0]["subject"],
                text="Step-up required by policy: " + _describe(matches["challenge"]),
                context=dict(score=0.0, force_challenge=True, matched=matches["challenge"]),
            ))
        if matches.get("allow"):
            messages.append(Message(
                code="policy_allow",
                path=matches["allow"][0]["subject"],
                text="Review and challenge waived by policy: " + _describe(matches["allow"]),
                context=dict(score=0.0, allow=True, matched=matches["allow"]),
            ))

        return messages


def _describe(matches):
    return "; ".join(
        f"{m['layer']} {m['subject']}={m['pattern']}" + (f" ({m['reason']})" if m.get("reason") else "")
        for m in matches[:3]
    )
