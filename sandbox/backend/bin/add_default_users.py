import sys
sys.path.append('..')
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'backend.settings'

import django
django.setup()

from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType


content_type = ContentType.objects.get_for_model(User)
can_view = Permission.objects.create(
    codename='can_view_data',
    name='Can View Data',
    content_type=content_type,
)

User.objects.all().delete()

# view_per = Permission.objects.get(name='Can view files')
# add_per = Permission.objects.get(name='Can add files')

alice = User.objects.create_user(
    username='alice',
    password='pass'
)
alice.save()
alice.user_permissions.add(can_view)
alice.save()

bob = User.objects.create_user(
    username='bob',
    password='pass'
)
bob.save()
