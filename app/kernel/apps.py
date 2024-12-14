from django.apps import AppConfig


class KernelConfig(AppConfig):
    def ready(self):
        from core import signals as signals
        from kernel import config as config

    name = "kernel"
    verbose_name = "Kernel"
    default_auto_field = "django.db.models.BigAutoField"
