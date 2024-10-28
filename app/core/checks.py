from bootkit.checks import is_uuid_string


def is_existing_record_id(model_class, id):
    return (
        is_uuid_string(str(id))
        and model_class.objects.filter(id=str(id)).exists()
    )
