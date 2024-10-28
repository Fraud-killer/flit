from uuid import uuid4
from bootkit import execute
from django.db import models

from .user import User


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=80)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    owner = models.ForeignKey(User, on_delete=models.PROTECT)

    def __str__(self):
        owner = execute(lambda: self.owner)[0]
        return f"{self.name} ({owner.email if owner else None})"
