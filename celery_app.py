import os

from celery import Celery
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'oneid.settings')
app = Celery(
    'oneid',
    include={
        'tasksapp.tasks',
        'ldap.sql_backend.scripts',
    },
)
app.config_from_object(settings, namespace='CELERY')
