# The calibrator: what an application has learned from its own outcomes, and
# the ledger of every run that learned it.

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0012_enforcement_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='policy',
            name='calibration',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.CreateModel(
            name='CalibrationRun',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('started_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('window_days', models.IntegerField()),
                ('decisions', models.IntegerField(default=0)),
                ('labelled', models.IntegerField(default=0)),
                ('fraud', models.IntegerField(default=0)),
                ('legit', models.IntegerField(default=0)),
                ('mode', models.CharField(choices=[('dry_run', 'Dry run — computed, not applied'), ('applied', 'Applied — the policy was changed'), ('held', 'Held — the evidence did not justify a change')], default='dry_run', max_length=20)),
                ('reason', models.TextField(blank=True, default='')),
                ('proposals', models.JSONField(blank=True, default=list)),
                ('before', models.JSONField(blank=True, default=dict)),
                ('after', models.JSONField(blank=True, default=dict)),
                ('threshold_sweep', models.JSONField(blank=True, default=list)),
                ('measured', models.JSONField(blank=True, default=list)),
                ('applied', models.BooleanField(default=False)),
                ('applied_at', models.DateTimeField(blank=True, null=True)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='calibration_runs', to='core.application')),
            ],
            options={
                'ordering': ['-started_at'],
                'indexes': [models.Index(fields=['application', 'started_at'], name='core_calibr_applica_f10018_idx')],
            },
        ),
    ]
