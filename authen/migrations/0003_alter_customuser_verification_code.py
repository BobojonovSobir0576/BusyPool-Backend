# Generated by Django 5.0.7 on 2024-08-12 11:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authen', '0002_customuser_verification_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='verification_code',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
    ]
