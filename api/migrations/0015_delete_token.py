# Generated by Django 4.0.5 on 2022-08-31 02:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_domain_pas_reset_domain_verified_user_pas_reset'),
    ]

    operations = [
        migrations.DeleteModel(
            name='token',
        ),
    ]
