from core.auth.actor import Actor
from rest_framework_simplejwt import authentication


class JwtAuthentication(authentication.JWTAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        return (None, Actor(result[0])) if result else None
