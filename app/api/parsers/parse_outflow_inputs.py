from devkit.checks import is_uuid_str
from devkit.struct import Struct

from core.messages.outflow import msg_beneficiary_entries, msg_outflow_trip_exist
from core.models import OutflowTrip

from .parse_application_id import parse_application_id


MAX_BENEFICIARIES = 1000
MAX_ID_LENGTH = 128


def parse_outflow_trip_inputs(id, trip_id, request):
    errors = list()
    application = parse_application_id(id, errors)
    trip = None

    if application and is_uuid_str(trip_id):
        trip = OutflowTrip.objects.filter(id=trip_id, application=application).first()
    if application and trip is None:
        errors.append(msg_outflow_trip_exist.new(path="trip_id"))

    body = request.data if isinstance(request.data, dict) else {}
    note = body.get("note")

    data = None if errors else Struct(
        application=application, trip=trip, note=note if isinstance(note, str) else "",
    )
    return (data, errors)


def is_short_id(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= MAX_ID_LENGTH


def valid_entry(entry):
    if not isinstance(entry, dict):
        return False
    required = ("initiator_id", "client_id", "counterparty_id")
    bank = entry.get("counterparty_bank")
    return all(is_short_id(entry.get(name)) for name in required) and (bank is None or is_short_id(bank))


def parse_beneficiary_inputs(id, request):
    errors = list()
    application = parse_application_id(id, errors)

    body = request.data if isinstance(request.data, dict) else {}
    entries = body.get("beneficiaries")

    if not (isinstance(entries, list) and 0 < len(entries) <= MAX_BENEFICIARIES
            and all(valid_entry(entry) for entry in entries)):
        errors.append(msg_beneficiary_entries)

    data = None if errors else Struct(application=application, entries=entries)
    return (data, errors)
