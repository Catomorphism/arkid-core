# Generated by Django 2.0.7 on 2019-02-01 04:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oneid_meta', '0010_auto_20190129_1556'),
    ]

    operations = [
        migrations.AddField(
            model_name='perm',
            name='subject',
            field=models.CharField(blank=True, default='default', max_length=255, verbose_name='权限分类'),
        ),
    ]
