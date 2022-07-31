import sys
sys.path.append('..')
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'backend.settings'

import django
django.setup()

from django.contrib.auth.models import User


User.objects.all().delete()

alice = User.objects.create_user(
    username='alice',
    password='pass'
)
alice.save()

bob = User.objects.create_user(
    username='bob',
    password='pass'
)
bob.save()
