# Generated by Django 3.1.6 on 2022-10-01 21:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ssl_monitor', '0002_certmonitor_expirationdate'),
    ]

    operations = [
        migrations.AddField(
            model_name='certmonitor',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='auth.user'),
            preserve_default=False,),
            ]