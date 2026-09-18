import uuid
from django.db import migrations, models
import django.db.models.deletion

import core.models.application


def populate_collect_keys(apps, schema_editor):
    """Every application needs its own key, so they cannot share one default."""
    Application = apps.get_model("core", "Application")

    for application in Application.objects.filter(collect_key=None):
        application.collect_key = core.models.application.generate_collect_key()
        application.save(update_fields=["collect_key"])


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_device_graph"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeviceSignature",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("signature_hash", models.CharField(db_index=True, max_length=64)),
                ("components", models.JSONField(default=dict)),
                ("platform", models.CharField(blank=True, max_length=40)),
                ("event_count", models.PositiveIntegerField(default=0)),
                ("first_seen_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen_at", models.DateTimeField(auto_now=True)),
                ("application", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="core.application")),
                ("device", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="signatures", to="core.deviceidentity")),
            ],
        ),
        migrations.AddIndex(
            model_name="devicesignature",
            index=models.Index(
                fields=["application", "platform", "last_seen_at"],
                name="core_device_applica_66f02b_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="devicesignature",
            constraint=models.UniqueConstraint(
                fields=("application", "signature_hash"),
                name="unique_device_signature_per_application",
            ),
        ),
        migrations.AlterField(
            model_name="deviceidentity",
            name="source",
            field=models.CharField(
                choices=[("fingerprint", "Fingerprint"), ("flit", "FLIT SDK")],
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="application",
            name="collect_key",
            field=models.CharField(max_length=64, null=True),
        ),
        migrations.RunPython(populate_collect_keys, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="application",
            name="collect_key",
            field=models.CharField(
                default=core.models.application.generate_collect_key,
                max_length=64,
                unique=True,
            ),
        ),
    ]
