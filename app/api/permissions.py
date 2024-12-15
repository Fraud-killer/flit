from core.auth.actor import Actor
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import NotAuthenticated

class HasAuthenticated(BasePermission):
    def has_permission(self, request, view):
        if isinstance(request.auth, Actor): return True
        raise NotAuthenticated("No matching authentication scheme")
