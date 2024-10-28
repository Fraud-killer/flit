from django.apps import AppConfig


class KernelConfig(AppConfig):
    def ready(self):
        from core import config as config
        from core import signals as signals

    name = "kernel"
    verbose_name = "Kernel"
    default_auto_field = "django.db.models.BigAutoField"
