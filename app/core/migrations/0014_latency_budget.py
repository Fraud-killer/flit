# A decision has a deadline. Rules that outlive it are reported as unavailable
# rather than holding the payment open.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0013_calibration'),
    ]

    operations = [
        migrations.AddField(
            model_name='policy',
            name='latency_budget_ms',
            field=models.IntegerField(default=3000),
        ),
    ]
