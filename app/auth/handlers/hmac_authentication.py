import signit
from kernel import mcrypt
from auth.actor import Actor
from core.models import Application
from devkit.checks import is_uuid_string
from devkit import execute, create_hash_value
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication


class HmacAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return "HMAC realm='api'"

    def prepare_application(self, client_id):
        if not is_uuid_string(client_id):
            return None

        application = Application.objects.filter(
            id=client_id
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

        client_id, message_hash = result[1:]

        request_hash = create_hash_value(
            dict(
                path=request.path.lower(),
                method=request.method.lower(),
                body_hash=create_hash_value(request.data),
                timestamp=request.headers.get("X-Timestamp"),
                client_id=request.headers.get("X-Client-Id"),
                content_type=request.headers.get("Content-Type"),
            )
        )

        actor = None

        for prepare in [self.prepare_application]:
            result = prepare(client_id)

            if result is not None:
                if signit.signature.verify(
                    message_hash,
                    result[1],
                    request_hash,
                ):
                    actor = result[0]

                break  # Redundant to continue iteration
        
        if actor: return (None, actor)

        raise AuthenticationFailed("Invalid credentials")
