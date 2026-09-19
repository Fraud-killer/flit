# FLIT detection coverage

Generated from the registered rules by `python manage.py coverage_matrix`. Do not edit by hand — a coverage document that is written rather than derived starts lying the first time a rule changes.

Mapped against **MITRE Fight Fraud Framework (F3) v1.1**. FLIT does not define its own fraud taxonomy; it maps onto the one the industry already uses ([source](https://github.com/center-for-threat-informed-defense/fight-fraud-framework)).

## Where FLIT stands

| | Techniques |
|---|---|
| Covered by at least one detector | **19** |
| Addressable, not yet covered | 25 |
| Outside FLIT's telemetry | 30 |
| **In scope** (covered + addressable) | **44** |
| F3 techniques in total | 74 |

Coverage of what FLIT can see: **43%** (19/44).

Of the 19 covered techniques, **1** rest on a detector with measured precision and recall. The rest are reasoned but not yet measured — see the ladder below.

## Evidence ladder

| Rung | Detectors | What it requires |
|---|---|---|
| Proposed | 13 | Reasoned from how the fraud works. No evidence yet. |
| Synthetic-tested | 27 | Fires on a constructed example of the technique and stays quiet on a constructed legitimate lookalike. |
| Historically backtested | 1 | Run against a merchant's labelled history, with measured precision and recall at the shipped threshold. |
| Shadow-validated | 0 | Run against live traffic without acting on it, and reviewed. |
| Production-observed | 0 | Acting in production, with its decisions labelled by reviewers. |
| Outcome-calibrated | 0 | Thresholds set from confirmed outcomes rather than judgement, and re-measured on a schedule. |

`Proposed` is not a criticism. It means the detector is reasoned from how the fraud works and has not been measured against labelled history yet. Nothing above that rung may be claimed without naming the evidence, and the test suite enforces it.

## Covered techniques

| F3 | Technique | Tactic | Evidence | Detectors |
|---|---|---|---|---|
| `F1001` | 3DS Bypass | Stealth | Synthetic-tested | ThreeDSTimeoutRule |
| `F1002` | Abuse of Public-Facing API | Positioning, Initial Access, Execution | Synthetic-tested | BotSignalRule, ExpectedSignalRule |
| `F1005` | Account Manipulation | Positioning, Defense Impairment | Synthetic-tested | AccountTakeoverRule, NewWithdrawalAddressRule |
| `F1006` | Account Takeover | Initial Access | Synthetic-tested | AccountSharingRule, AccountTakeoverRule, DeviceExpiredRule, NewDeviceCountryRule, UnregisteredDeviceRule |
| `F1012` | Card Testing | Positioning | Synthetic-tested | CardTestingRule, IssuerSignalRule, RetryAttackRule |
| `F1016` | Compromise Payment Gateway | Initial Access | Synthetic-tested | GatewayPatternRule |
| `F1018` | Convert to Cryptocurrency | Monetization | Synthetic-tested | CryptoCashOutRule |
| `F1020` | Create Fake Materials | Resource Development | Synthetic-tested | FakeAddressRule |
| `F1023` | Device Fingerprint Spoofing | Stealth | Synthetic-tested | DeviceConsistencyRule, DeviceTamperingRule, ExpectedSignalRule |
| `F1025` | Electronic Funds Transfer | Monetization | Synthetic-tested | PassThroughRule |
| `F1028` | Fradulent Purchasing | Monetization, Execution | Synthetic-tested | GatewayPatternRule, IssuerSignalRule, PaymentFraudRule |
| `F1030` | Geolocation Spoofing | Stealth | Synthetic-tested | IPReputationRule, ImpossibleTravelRule |
| `F1039` | PaReq Manipulation | Stealth | Synthetic-tested | ThreeDSTimeoutRule |
| `F1042` | Reactivate Account | Positioning, Initial Access | Synthetic-tested | DormantAwakeningRule |
| `F1045` | Structuring | Stealth | Historically backtested | StructuringRule |
| `F1047` | Transfer of funds | Monetization | Synthetic-tested | CollectionWalletRule, MuleNetworkRule, PassThroughRule |
| `T1110` | Brute Force | Initial Access | Proposed | VelocityCheckRule |
| `T1583` | Acquire Infrastructure | Resource Development | Synthetic-tested | DomainReputationRule, FreshFundingWalletRule, IPConcentrationRule, IPReputationRule |
| `T1585` | Establish Accounts | Resource Development | Synthetic-tested | AccountFarmingRule, AccountSharingRule, DisposableEmailRule, DomainReputationRule, EmailPatternRule, FreshFundingWalletRule, MultiAccountingRule |

## Addressable, not yet covered

FLIT already receives signals that could detect these. This is the roadmap, in priority order set by whoever is reading it.

| F3 | Technique | Tactic |
|---|---|---|
| `F1003` | Abuse SMS verification | Execution |
| `F1004` | Access with Stolen Session Cookie | Initial Access |
| `F1007` | Adversary-in-the-Browser | Positioning, Initial Access, Execution |
| `F1015` | Churning | Execution |
| `F1021` | Create Fraudulent Merchant Account | Resource Development |
| `F1024` | Dispute Legitimate Transaction | Execution |
| `F1031` | Impersonate Account Holder | Initial Access, Stealth |
| `F1036` | New Vendor Setup | Positioning, Stealth |
| `F1038` | PAN/CVV Generation | Resource Development |
| `F1043` | Reversal of Transaction | Execution |
| `F1044` | Scheduled Transfer | Execution |
| `F1046` | Test Payment Thresholds | Positioning |
| `F1048` | Use Virtual Cards | Stealth |
| `T1070` | Indicator Removal | Stealth |
| `T1111` | Multi-Factor Authentication Interception | Initial Access |
| `T1185` | Browser Session Hijacking | Positioning, Initial Access |
| `T1219` | Remote Access Tools | Positioning |
| `T1451` | SIM Card Swap | Initial Access |
| `T1453` | Abuse Accessibility Features | Positioning |
| `T1531` | Account Access Removal | Positioning |
| `T1539` | Steal Web Session Cookie | Positioning, Initial Access |
| `T1550` | Use Alternate Authentication Material | Initial Access |
| `T1557` | Adversary-in-the-Middle | Positioning, Initial Access, Execution |
| `T1586` | Compromise Accounts | Resource Development |
| `T1621` | Multi-Factor Authentication Request Generation | Initial Access |

## Outside FLIT's telemetry

These happen where a server-side decision layer has no eyes. They are listed so the boundary is explicit rather than implied, and each reason can be argued with.

| F3 | Technique | Why |
|---|---|---|
| `F1008` | ATM Manipulation | ATM hardware; FLIT sees no device-level ATM telemetry |
| `F1009` | Bank Deposit | Physical and branch deposit channels |
| `F1010` | Buy Money Order | Purchased at a physical counter |
| `F1011` | Card Dump Capture | Card data captured offline, before any transaction |
| `F1013` | Change Payroll Details | Happens in a payroll system, not the payment platform |
| `F1014` | Check Fraud | Paper instruments |
| `F1017` | Conversion to Physical Monetary Instruments | Cash and physical instruments |
| `F1019` | Create Counterfeit Card | Card manufactured offline |
| `F1022` | Delete Relevant Emails | Requires mailbox access |
| `F1026` | Exploitation of Gambling Platforms | Occurs on a third-party gambling platform |
| `F1027` | Falsify Business Documents | Document review sits with the KYB provider |
| `F1029` | Gather Customer Information | Reconnaissance carried out off-platform |
| `F1032` | Impersonate Official | Social engineering outside the product surface |
| `F1033` | Insider Access Abuse | Needs the operator's internal admin logs, not customer traffic |
| `F1034` | Interactive Voice Response Mapping | Voice channel |
| `F1035` | Mail Theft | Physical mail |
| `F1037` | NFC Payment | Card-present NFC; FLIT is a card-not-present decision layer |
| `F1040` | Phone Number Spoofing | Telephony infrastructure |
| `F1041` | PIN-code Peeking | Physical observation |
| `T1113` | Screen Capture | Endpoint capture, invisible to a server-side decision |
| `T1189` | Drive-by Compromise | Endpoint compromise |
| `T1195` | Supply Chain Compromise | Vendor supply chain |
| `T1555` | Credentials from Password Stores | Endpoint credential stores |
| `T1593` | Search Open Websites/Domains | Open-source reconnaissance |
| `T1598` | Phishing for Information | Phishing carried out off-platform |
| `T1608` | Stage Capabilities | Attacker-side infrastructure |
| `T1650` | Acquire Access | Access bought in criminal markets |
| `T1660` | Phishing | Phishing carried out off-platform |
| `T1667` | Email Bombing | Requires mailbox visibility |
| `T1672` | Email Spoofing | Mail infrastructure |

## Detectors

| Rule | Kind | F3 | Evidence | Shown by |
|---|---|---|---|---|
| AccountFarmingRule | detection | `T1585` | Synthetic-tested | tests/unit/test_mule_detection.py::TestAccountFarmingRule; tests/unit/test_signup_defence.py::TestIdentityLadder |
| AccountSharingRule | detection | `F1006`, `T1585` | Synthetic-tested | tests/unit/test_device_graph.py::TestAccountSharingRule |
| AccountTakeoverRule | detection | `F1006`, `F1005` | Proposed | — |
| AmlCftLimitExceededRule | control | — | Proposed | — |
| BotSignalRule | detection | `F1002` | Synthetic-tested | tests/unit/test_intelligence.py::TestBotSignalRule |
| CardTestingRule | detection | `F1012` | Proposed | — |
| ChallengeEvasionRule | corroboration | — | Synthetic-tested | tests/unit/test_challenges.py::TestTheLoopCloses |
| CollectionWalletRule | detection | `F1047` | Synthetic-tested | tests/unit/test_crypto.py::TestCollectionWallet |
| CryptoCashOutRule | detection | `F1018` | Synthetic-tested | tests/unit/test_crypto.py::TestCryptoCashOut |
| DeviceConsistencyRule | detection | `F1023` | Synthetic-tested | tests/unit/test_device_collection.py::TestConsistencyChecks |
| DeviceExpiredRule | detection | `F1006` | Proposed | — |
| DeviceTamperingRule | detection | `F1023` | Synthetic-tested | tests/unit/test_device_graph.py::TestDeviceIntegrity |
| DisposableEmailRule | detection | `T1585` | Synthetic-tested | tests/unit/test_signup_defence.py::TestSeptember2026Replay |
| DomainReputationRule | detection | `T1585`, `T1583` | Synthetic-tested | tests/unit/test_domain_intelligence.py::TestDomainReputationRule |
| DormantAwakeningRule | detection | `F1042` | Synthetic-tested | tests/unit/test_mule_detection.py::TestDormantAwakeningRule |
| EmailPatternRule | detection | `T1585` | Synthetic-tested | tests/unit/test_signup_defence.py::TestEmailIntelligence |
| ExpectedSignalRule | detection | `F1002`, `F1023` | Synthetic-tested | tests/unit/test_signup_defence.py::TestAbsenceAsEvidence |
| FakeAddressRule | detection | `F1020` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestFakeAddressRule |
| FreshFundingWalletRule | detection | `T1583`, `T1585` | Synthetic-tested | tests/unit/test_wallet_history.py::TestFreshFundingWalletRule |
| GatewayPatternRule | detection | `F1016`, `F1028` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestGatewayPatternRule |
| IPConcentrationRule | detection | `T1583` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestIPConcentrationRule |
| IPReputationRule | detection | `T1583`, `F1030` | Synthetic-tested | tests/unit/test_intelligence.py::TestIPReputationRule |
| ImpossibleTravelRule | detection | `F1030` | Proposed | — |
| IssuerSignalRule | detection | `F1012`, `F1028` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestIssuerSignalRule |
| MaximumCumulativeBalanceExceededRule | control | — | Proposed | — |
| MaximumDailyCumulativeDebitExceededRule | control | — | Proposed | — |
| MaximumSingleCreditExceededRule | control | — | Proposed | — |
| MaximumSingleDebitExceededRule | control | — | Proposed | — |
| MuleNetworkRule | detection | `F1047` | Synthetic-tested | tests/unit/test_mule_detection.py::TestMuleNetworkRule |
| MultiAccountingRule | detection | `T1585` | Synthetic-tested | tests/unit/test_device_graph.py::TestMultiAccountingRule; tests/unit/test_signup_defence.py::TestIdentityLadder |
| NetworkReputationRule | corroboration | — | Synthetic-tested | tests/unit/test_protection_network.py |
| NewDeviceCountryRule | detection | `F1006` | Proposed | — |
| NewWithdrawalAddressRule | detection | `F1005` | Synthetic-tested | tests/unit/test_crypto.py::TestNewWithdrawalAddress |
| PassThroughRule | detection | `F1047`, `F1025` | Synthetic-tested | tests/unit/test_mule_detection.py::TestPassThroughRule |
| PaymentFraudRule | detection | `F1028` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestPaymentFraudRule |
| RetryAttackRule | detection | `F1012` | Proposed | — |
| SanctionedAddressRule | control | — | Synthetic-tested | tests/unit/test_sanctions.py::TestSanctionedAddressRule |
| StructuringRule | detection | `F1045` | Historically backtested | Replayed against 11,868 labelled Figo transactions (2026-02-01 to 2026-09-19, 235 fraud / 11,408 legit): fired 56 times, 12 on fraud, lift 13.1, precision 0.214. The only rule in FLIT with measured lift above 1 on that portfolio. Also tests/unit/test_mule_detection.py::TestStructuringRule. |
| ThreeDSTimeoutRule | detection | `F1001`, `F1039` | Synthetic-tested | tests/unit/test_fraud_rules.py::TestThreeDSTimeoutRule |
| UnregisteredDeviceRule | detection | `F1006` | Proposed | — |
| VelocityCheckRule | detection | `T1110` | Proposed | — |

