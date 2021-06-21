Customization
=============

djwto offers the possibility for the client to customize how parts of the code should be processed, replacing the original logic. Just as discussed in :ref:`signals`, let's suppose a regular Django project with an app called *testapp*.

It's possible to specify customizations for djwto when the app is `ready <https://docs.djangoproject.com/en/3.2/ref/applications/#django.apps.AppConfig.ready>`_. For instance, if your project requires to also bring the customer's email when the JWT creation is running, here's one way of doing it:

.. code-block::

  from django.apps import AppConfig


  class TestappConfig(AppConfig):
      default_auto_field = 'django.db.models.BigAutoField'
      name = 'testapp'

      def ready(self):
          import djwto.tokens as tokens


          def new_process_user(user):
              return {
                  user.USERNAME_FIELD: user.get_username(),
                  'email': user.email,
                  'id': user.pk,
                  'perms': tokens.process_perms(user)
              }

          tokens.process_claims = new_process_user

Running the loggin process for ``TWO-COOKIES``, we get now:

.. code-block::

  import requests
  import base64


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": 1624259339, "iat": 1624229339, "iss": "iss", "jti": "900f4f1a-3e0f-4843-9997-9fd8d032684e", "refresh_iat": 1624229339, "sub": "sub", "type": "access", "user": {"email": "alice@djwto.com", "id": 1, "perms": [], "username": "alice"}}'

Feel free to customize the code as you see fit.
