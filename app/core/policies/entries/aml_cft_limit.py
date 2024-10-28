from bootkit import execute
from core.money import Money
from core.mezages import mzg_money
from bootkit.mezages import mzg_mapping, mzg_req_prop, mzg_unexpected_props


class AmlCftLimit:
    key = "aml_cft_limit"
    default = dict(value="NGN 5,000,000")

    @classmethod
    def validate(cls, data):
        if not isinstance(data, dict):
            return [mzg_mapping.new()]

        errors = list()

        if "value" not in data:
            errors.append(
               mzg_req_prop.new(target="value")
            )
        elif execute(Money, data["value"])[1]:
            errors.append(mzg_money.new(target="value"))

        unexpected_props = list(set(data) - {"value"})

        if unexpected_props:
            errors.append(
                mzg_unexpected_props.new(
                    context=dict(
                        unexpected_properties=unexpected_props
                    )
                )
            )

        return errors
