# Generated by Django 4.1.1 on 2022-09-16 08:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_alter_user_managers_remove_user_username_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitation',
            name='created_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
