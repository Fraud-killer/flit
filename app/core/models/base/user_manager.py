from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, **kwargs):
        email = kwargs.pop("email")
        password = kwargs.pop("password")
        email = self.normalize_email(email)

        user = self.model(**kwargs, email=email)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, **kwargs):
        kwargs["is_staff"] = True
        kwargs["is_active"] = True
        kwargs["is_superuser"] = True

        return self.create_user(**kwargs)
