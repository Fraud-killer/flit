from bootkit import undefined
from core.audit import auditors
from core.audit import validators
from bootkit.struct import Struct
from core.models import Application
from core.guards import ApplicationGuard
from bootkit.mezage import mount_targets
from bootkit.checks import is_uuid_string
from core.applications.mezages import mzg_app_ref_exist
from bootkit.mezages import mzg_uuid, mzg_in_choices, mzg_req_prop


class AuditMarshal:
    AUDIT_TYPES_DICT = {
        "end-user": Struct(
            auditor=auditors.end_user_auditor,
            validator=validators.validate_end_user_audit_data,
        ),
        "transaction": Struct(
            auditor=auditors.transaction_auditor,
            validator=validators.validate_transaction_audit_data,
        )
    }

    def __init__(self, *, request, audit_type):
        self.request = request
        self.audit_options = self.AUDIT_TYPES_DICT.get(audit_type)

    def audit(self, inputs):
        data = inputs.data
        policy = inputs.application.policy
        auditor = self.audit_options.auditor
        return dict(auditor.audit(data, policy))

    def ensure_access(self, inputs):
        actor = self.request.auth
        resource = inputs.application
        ApplicationGuard(actor, resource).can_manage()

    def parse_inputs(self):
        errors = list()
        application = None

        data = self.request.data.get("data", undefined)
        application_id = self.request.data.get("application_id", undefined)

        if not self.audit_options:
            errors.append(
                mzg_in_choices.new(target="audit_type", context=dict(
                    choices=list(self.AUDIT_TYPES_DICT.keys())
                ))
            )

        if application_id is undefined:
            errors.append(
                mzg_req_prop.new(target="application_id")
            )
        elif not is_uuid_string(application_id):
            errors.append(
                mzg_uuid.new(target="application_id")
            )
        else:
            application = Application.objects.filter(id=application_id).first()

            if not application:
                errors.append(mzg_app_ref_exist.new(target="application_id"))

        if data is undefined:
            errors.append(
                mzg_req_prop.new(target="data")
            )
        elif self.audit_options:
            data_errors = self.audit_options.validator(data, application.policy if application else None)
            errors.extend(mount_targets(data_errors, "data"))

        inputs = None if errors else Struct(data=data, application=application)
    
        return (inputs, errors)
