import signit
from core import mcrypt
from core.auth.actor import Actor
from core.models import Application
from devkit.checks import is_uuid_str
from devkit import execute, create_hash_value
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication


class HmacAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return "HMAC realm='api'"

    def prepare_application(self, public_key):
        if not is_uuid_str(public_key):
            return None

        application = Application.objects.filter(
            id=public_key
        ).first()

        if not application: return None

        auth_entity = Actor(application)
        secret_key = mcrypt.decrypt(application.secret_key)

        return (auth_entity, secret_key)

    def authenticate(self, request):
        auth_value = request.headers.get("Authorization")

        if (
            not isinstance(auth_value, str)
            or not auth_value.startswith("HMAC-SHA256")
        ):
            return None

        result, error = execute(signit.signature.parse, auth_value)

        if error or len(result) != 3:
            raise AuthenticationFailed("Invalid signature format")

        public_key, signed_message_hash = result[1:]

        message_hash = create_hash_value(
            dict(
                path=request.path.lower(),
                method=request.method.lower(),
                body_hash=create_hash_value(request.data),
                timestamp=request.headers.get("X-Timestamp"),
                content_type=request.headers.get("Content-Type"),
            )
        )

        actor = None

        for prepare in [self.prepare_application]:
            prepared = prepare(public_key)

            if prepared is not None:
                secret_key = prepared[1]

                if signit.signature.verify(
                    signed_message_hash,
                    secret_key,
                    message_hash,
                ):
                    actor = prepared[0]

                break  # Redundant to continue iteration

        if actor: return (None, actor)

        raise AuthenticationFailed("Invalid credentials")
