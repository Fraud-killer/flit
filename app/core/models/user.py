from uuid import uuid4
from django.db import models
from django.contrib.auth.models import AbstractUser

from .base.user_manager import UserManager


class User(AbstractUser):
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["password"]

    # is_staff
    # is_active
    # last_login
    # date_joined
    # is_superuser

    groups = None
    username = None
    last_name = None
    first_name = None
    user_permissions = None

    objects = UserManager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=256)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.email
