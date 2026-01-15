from django.db import migrations, models
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('level', models.CharField(choices=[('debug', 'Debug'), ('info', 'Info'), ('warning', 'Warning'), ('error', 'Error'), ('critical', 'Critical')], db_index=True, max_length=20)),
                ('category', models.CharField(choices=[('authentication', 'Authentication'), ('authorization', 'Authorization'), ('transaction', 'Transaction'), ('device', 'Device'), ('policy', 'Policy'), ('security', 'Security'), ('system', 'System')], db_index=True, max_length=50)),
                ('action', models.CharField(db_index=True, max_length=100)),
                ('actor_type', models.CharField(blank=True, max_length=50, null=True)),
                ('actor_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('resource_type', models.CharField(blank=True, max_length=50, null=True)),
                ('resource_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('application_id', models.UUIDField(blank=True, db_index=True, null=True)),
                ('organization_id', models.UUIDField(blank=True, db_index=True, null=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('device_fingerprint', models.CharField(blank=True, max_length=100, null=True)),
                ('request_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('request_method', models.CharField(blank=True, max_length=10, null=True)),
                ('request_path', models.CharField(blank=True, max_length=500, null=True)),
                ('context', models.JSONField(default=dict)),
                ('risk_score', models.FloatField(blank=True, null=True)),
                ('risk_factors', models.JSONField(default=list)),
                ('outcome', models.CharField(blank=True, max_length=50, null=True)),
                ('error_code', models.CharField(blank=True, max_length=50, null=True)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('previous_hash', models.CharField(blank=True, max_length=64, null=True)),
                ('entry_hash', models.CharField(editable=False, max_length=64)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='AuditLogArchive',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('archive_date', models.DateField(db_index=True)),
                ('start_timestamp', models.DateTimeField()),
                ('end_timestamp', models.DateTimeField()),
                ('record_count', models.IntegerField()),
                ('file_path', models.CharField(max_length=500)),
                ('file_hash', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-archive_date'],
            },
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['application_id', 'timestamp'], name='core_audit__applica_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['actor_id', 'timestamp'], name='core_audit__actor_i_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['category', 'action', 'timestamp'], name='core_audit__categor_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['risk_score'], name='core_audit__risk_sc_idx'),
        ),
    ]
