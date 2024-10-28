from django.dispatch import receiver
from core.models import Policy, Application
from django.db.models.signals import post_save


@receiver(post_save, sender=Application)
def create_policy_on_app_create(sender, instance, created, **kwargs):
    if created:
        policy = Policy(application=instance)
        policy.full_clean()
        policy.save()
