from devkit.checks import is_uuid_str


def is_existing_record_id(model_class, id):
    return (
        is_uuid_str(str(id))
        and model_class.objects.filter(id=str(id)).exists()
    )
