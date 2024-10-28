from core.audit import rules
from core.audit.auditor import Auditor


end_user_auditor = Auditor([
    rules.NewDeviceRule,
    rules.ExpiredDeviceRule,
    rules.NewDeviceCountryRule,
])


transaction_auditor = Auditor([
    rules.NewDeviceRule,
    rules.ExpiredDeviceRule,
    rules.NewDeviceCountryRule,
    rules.AmlCftLimitExceededRule,
    rules.KycMaxSingleDebitExceededRule,
    rules.KycMaxSingleCreditExceededRule,
    rules.KycMaxCummulativeBalanceExceededRule,
    rules.KycMaxDailyCummulativeDebitExceededRule,
])
