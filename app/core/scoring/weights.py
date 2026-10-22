from dataclasses import dataclass, field
from typing import Dict, Optional

from core.identity_keys import IdentityKeyType


@dataclass
class RiskWeights:
    device_expired: float = 0.3
    new_device_country: float = 0.4
    unregistered_device: float = 0.5
    aml_cft_limit_exceeded: float = 0.9
    maximum_single_debit_exceeded: float = 0.7
    maximum_single_credit_exceeded: float = 0.6
    maximum_cumulative_balance_exceeded: float = 0.8
    maximum_daily_cumulative_debit_exceeded: float = 0.7
    velocity_exceeded: float = 0.6
    impossible_travel: float = 0.85
    account_takeover: float = 0.95
    multiple_devices: float = 0.5
    multiple_ips: float = 0.4
    high_failure_rate: float = 0.6
    tor_exit_node: float = 0.8
    known_attacker: float = 0.9
    proxy_detected: float = 0.5
    vpn_detected: float = 0.4
    datacenter_ip: float = 0.3
    # A client address no end user can have. Not a risk signal about the
    # actor's location but proof the actor is writing the headers, which is
    # worth more than any location would be.
    implausible_client_ip: float = 0.9
    high_risk_country: float = 0.5
    bot_detected: float = 0.7
    multi_accounting: float = 0.7
    account_sharing: float = 0.5
    concurrent_devices: float = 0.7
    device_tampering: float = 0.8
    virtual_machine: float = 0.5
    emulator: float = 0.7
    jailbroken_device: float = 0.6
    hooking_framework: float = 0.9
    cloned_app: float = 0.7
    developer_tools: float = 0.3
    location_spoofing: float = 0.8
    remote_control: float = 0.85
    mitm_attack: float = 0.8
    spoofed_timezone: float = 0.7
    platform_mismatch: float = 0.6
    software_renderer: float = 0.5
    automation_markers: float = 0.8
    device_class_mismatch: float = 0.5
    # Travellers and expats trip this legitimately.
    locale_country_mismatch: float = 0.15
    pass_through_funds: float = 0.75
    many_unique_payers: float = 0.7
    credit_structuring: float = 0.55
    dormant_account_activity: float = 0.5
    account_farming: float = 0.8
    mule_network_device: float = 0.9
    # Signup surface. An event producing none of the identity signal this
    # merchant's own traffic normally produces — see ExpectedSignalRule.
    missing_expected_device_signal: float = 0.55
    reserved_email_domain: float = 0.7
    disposable_email_domain: float = 0.6
    generated_email_local_part: float = 0.65
    adversarial_email_local_part: float = 0.5
    # Ordinary hygiene for real users. It earns its keep on the identity
    # ladder, where the tag is collapsed so several tagged signups resolve to
    # one mailbox, not from its weight here.
    plus_tagged_email: float = 0.1
    domain_cannot_receive_mail: float = 0.6
    newly_registered_domain: float = 0.35
    # Crypto rails. An on-chain transfer is final, so the cost of being wrong
    # runs the other way from card: a missed cash-out is unrecoverable, while
    # a challenged one costs the customer a minute.
    crypto_cash_out: float = 0.7
    # A new destination is ordinary on its own. It is weighted to matter only
    # alongside something else, which is when it means a takeover.
    new_withdrawal_address: float = 0.45
    collection_wallet: float = 0.8
    # A first transaction is somebody's genuine first transaction, so this
    # is weighted to corroborate rather than to decide on its own.
    fresh_funding_wallet: float = 0.4
    # A sanctions hit is not a risk signal to be weighed against others.
    sanctioned_address: float = 1.0
    # Screening did not happen, or happened against a stale list. Reported
    # on the decision, never scored — the point is that it is visible.
    sanctions_screening_unavailable: float = 0.0
    sanctions_list_stale: float = 0.0
    # Corroboration from other merchants: the one kind of evidence that did
    # not come from the merchant being protected. Weighted so that the
    # k-anonymity floor of two contributors lands on a challenge and further
    # corroboration escalates to a block — the network gets an actor verified,
    # not turned away, until more than the minimum of it agrees.
    network_fraud_history: float = 0.7
    challenge_evasion: float = 0.7
    # Credential surface. A reset that turns into a login faster than a
    # person reads an email is the takeover itself, not a hint of one, so it
    # is weighted to decide on its own.
    reset_then_login: float = 0.9
    # A script performing a credential action. Weighted below the interval
    # because a merchant's own integration test looks exactly like this.
    automated_credential_action: float = 0.8
    # One origin working through many accounts' credentials.
    credential_reset_storm: float = 0.85
    # Session shape. The whole session reads as automated: rotating clients,
    # machine cadence, accounts it did not create, the motif repeating. The
    # signal a fixed per-event threshold cannot be stepped over.
    machine_session: float = 0.85
    # The takeover motif — reset, login, then money or manipulation — seen
    # on two or more accounts from one origin. That is the attack itself.
    campaign_motif: float = 0.95
    # Data completeness, not evidence of fraud: reported, never scored.
    req_event_attrs: float = 0.0

    # Per-code overrides, used to try candidate weights without touching
    # the defaults (see core.services.simulate_policy).
    overrides: Dict[str, float] = field(default_factory=dict)

    category_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "transaction": 1.0,
        # A credential action is where a takeover happens, not a hint that
        # one might. Discounting it put a measured thirty-second
        # reset-to-login from a scripted client on a hosting provider under
        # the block line, so it is not discounted.
        "authentication": 1.0,
        "device": 0.7,
        "account": 0.9,
        # Registration abuse is the thing this category exists to catch, so
        # it is not discounted.
        "registration": 1.0,
    })

    time_decay_hours: float = 24.0
    recency_boost: float = 1.2

    def get_weight(self, rule_code: str, default: Optional[float] = None) -> float:
        """
        Weight for a rule code. Codes without a configured weight fall back to
        `default` (the score a rule attached to its message), then to 0.5.
        """
        if rule_code in self.overrides:
            return self.overrides[rule_code]

        if rule_code.startswith("bot_detected:"):
            return self.bot_detected

        # Correlation findings name the ladder rung they were found on, e.g.
        # `account_farming:ip`. The same shape is worth less on a weaker key,
        # so the base weight is scaled by that key's confidence rather than
        # each combination needing its own entry.
        for name, base in (
            ("account_farming", self.account_farming),
            ("multi_accounting", self.multi_accounting),
        ):
            if rule_code.startswith(f"{name}:"):
                key_type = rule_code.split(":", 1)[1]
                return round(base * IdentityKeyType.confidence(key_type), 4)

        weight_map = {
            "device_expired": self.device_expired,
            "new_device_country": self.new_device_country,
            "unregistered_device": self.unregistered_device,
            "aml_cft_limit_exceeded": self.aml_cft_limit_exceeded,
            "maximum_single_debit_exceeded": self.maximum_single_debit_exceeded,
            "maximum_single_credit_exceeded": self.maximum_single_credit_exceeded,
            "maximum_cumulative_balance_exceeded": self.maximum_cumulative_balance_exceeded,
            "maximum_daily_cumulative_debit_exceeded": self.maximum_daily_cumulative_debit_exceeded,
            "velocity_exceeded_per_minute": self.velocity_exceeded,
            "velocity_exceeded_per_5_minutes": self.velocity_exceeded,
            "velocity_exceeded_per_hour": self.velocity_exceeded,
            "velocity_exceeded_per_day": self.velocity_exceeded,
            "impossible_travel_detected": self.impossible_travel,
            "account_takeover_risk": self.account_takeover,
            "multiple_devices_detected": self.multiple_devices,
            "multiple_ips_detected": self.multiple_ips,
            "high_failure_rate": self.high_failure_rate,
            "tor_exit_node": self.tor_exit_node,
            "known_attacker": self.known_attacker,
            "proxy_detected": self.proxy_detected,
            "vpn_detected": self.vpn_detected,
            "datacenter_ip": self.datacenter_ip,
            "implausible_client_ip": self.implausible_client_ip,
            "high_risk_country": self.high_risk_country,
            "multi_accounting": self.multi_accounting,
            "account_sharing": self.account_sharing,
            "concurrent_devices": self.concurrent_devices,
            "device_tampering": self.device_tampering,
            "virtual_machine": self.virtual_machine,
            "emulator": self.emulator,
            "jailbroken_device": self.jailbroken_device,
            "hooking_framework": self.hooking_framework,
            "cloned_app": self.cloned_app,
            "developer_tools": self.developer_tools,
            "location_spoofing": self.location_spoofing,
            "remote_control": self.remote_control,
            "mitm_attack": self.mitm_attack,
            "spoofed_timezone": self.spoofed_timezone,
            "platform_mismatch": self.platform_mismatch,
            "software_renderer": self.software_renderer,
            "automation_markers": self.automation_markers,
            "device_class_mismatch": self.device_class_mismatch,
            "locale_country_mismatch": self.locale_country_mismatch,
            "pass_through_funds": self.pass_through_funds,
            "many_unique_payers": self.many_unique_payers,
            "credit_structuring": self.credit_structuring,
            "dormant_account_activity": self.dormant_account_activity,
            "account_farming": self.account_farming,
            "mule_network_device": self.mule_network_device,
            "missing_expected_device_signal": self.missing_expected_device_signal,
            "reserved_email_domain": self.reserved_email_domain,
            "disposable_email_domain": self.disposable_email_domain,
            "generated_email_local_part": self.generated_email_local_part,
            "adversarial_email_local_part": self.adversarial_email_local_part,
            "plus_tagged_email": self.plus_tagged_email,
            "domain_cannot_receive_mail": self.domain_cannot_receive_mail,
            "newly_registered_domain": self.newly_registered_domain,
            "crypto_cash_out": self.crypto_cash_out,
            "new_withdrawal_address": self.new_withdrawal_address,
            "collection_wallet": self.collection_wallet,
            "fresh_funding_wallet": self.fresh_funding_wallet,
            "sanctioned_address": self.sanctioned_address,
            "sanctions_screening_unavailable": self.sanctions_screening_unavailable,
            "sanctions_list_stale": self.sanctions_list_stale,
            "network_fraud_history": self.network_fraud_history,
            "challenge_evasion": self.challenge_evasion,
            "reset_then_login": self.reset_then_login,
            "automated_credential_action": self.automated_credential_action,
            "credential_reset_storm": self.credential_reset_storm,
            "machine_session": self.machine_session,
            "campaign_motif": self.campaign_motif,
            "req_event_attrs": self.req_event_attrs,
        }
        if rule_code in weight_map:
            return weight_map[rule_code]
        return 0.5 if default is None else default


@dataclass
class RiskThresholds:
    """
    Where a score turns into an action. These were implicit in RiskEngine
    (block at CRITICAL, review at HIGH); naming them lets an application tune
    them and lets a simulation try other values.
    """

    block_at: float = 0.7
    review_at: float = 0.5
    # Step-up verification. Sits below review because automated friction is
    # cheap enough to apply more widely than a human's attention, and it is
    # the right answer where evidence is real but thin — most of the signup
    # surface.
    challenge_at: float = 0.45


DEFAULT_WEIGHTS = RiskWeights()
DEFAULT_THRESHOLDS = RiskThresholds()
