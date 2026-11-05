from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0017_case_triage"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlog",
            name="loss_amount",
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True),
        ),
        migrations.AddField(
            model_name="auditlog",
            name="loss_currency",
            field=models.CharField(blank=True, max_length=3, null=True),
        ),
    ]
