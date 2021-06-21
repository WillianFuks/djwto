.. _signals:

Signals
=======

djwto offers by default a set of signals that you can use in your projects for tracking down when certain events take place. In order to demonstrate how it works, consider a regular Django project created with an app called ``testapp``. Its app config file is something like this:

.. code-block::

   # testapp/app.py

   from django.apps import AppConfig


   class TestappConfig(AppConfig):
       default_auto_field = 'django.db.models.BigAutoField'
       name = 'testapp'

       def ready(self):
           # Handlers for signals will be implemented here

Here's a list of all available signals offered by the package:

jwt_logged_in
-------------

The signal is triggered when a successfull loggin happens. Here's how to connect it:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_logged_in.connect(
          handler,
          sender='GetTokensView'
      )


Prints:

.. code-block:: shell

  sender:  GetTokensView
  this is kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7f6287e92910>, 'request': <WSGIRequest: POST '/login/'>, 'refresh_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624221463, 'exp': 1624307863, 'jti': '6eec0920-051a-4562-999d-b59fab51a5a8', 'type': 'refresh', 'user': {'username': 'alice', 'id': 1, 'perms': []}}, 'access_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624221463, 'exp': 1624251463, 'jti': '6eec0920-051a-4562-999d-b59fab51a5a8', 'type': 'access', 'user': {'username': 'alice', 'id': 1, 'perms': []}, 'refresh_iat': 1624221463}}

Notice that it requires a function (in this case, ``handler``) whose signature is the object ``sender`` and a set of keys represented by ``kwargs``. As djwto sends the signal from ``GetTokensView`` then this value must be set in the connection as well otherwise it won't listen to the events being sent.

jwt_login_fail
--------------

The signal is triggered when a loggin fails by any reason. Here's how to connect it:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_login_fail.connect(handler, sender='GetTokensView')

Supposing a scenario where the wrong password was sent, here's the expected printed results:

.. code-block:: shell

  sender:  GetTokensView
  kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7fcfd74b2610>, 'request': <WSGIRequest: POST '/login/'>, 'error': '{"__all__": ["Please enter a correct username and password. Note that both fields may be case-sensitive."]}'}

jwt_blacklisted
---------------

The signal is sent when a token is successfully blacklisted:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_blacklisted.connect(handler, sender='BlackListTokenView')

Example of what is printed:

.. code-block:: shell

  sender:  BlackListTokenView
  kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7f533b19a8e0>, 'request': <WSGIRequest: POST '/api/token/refresh/logout/'>, 'jti': 'ac9b42e9-82ee-4a9a-a75d-0d2a827a5f16'}

jwt_token_validated
-------------------

The signal is sent each time a validation request is processed:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_token_validated.connect(handler, sender='ValidateTokensView')

.. code-block:: shell

  sender:  ValidateTokensView
  kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7fed4e81ab50>, 'request': <WSGIRequest: POST '/validate_access/'>}

jwt_access_refreshed
--------------------

The signal is sent when the *access* token is successfully refreshed:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_access_refreshed.connect(handler, sender='RefreshAccessView')

Which prints:

.. code-block:: shell

  sender:  RefreshAccessView
  kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7f0eb01d6e20>, 'request': <WSGIRequest: POST '/api/token/refresh/refresh_access/'>, 'refresh_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624227492, 'exp': 1624313892, 'jti': '8a25e810-ced6-4f23-880d-5f8c2f9881fe', 'type': 'refresh', 'user': {'username': 'alice', 'id': 1, 'perms': []}}, 'access_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624227492, 'exp': 1624257492, 'jti': '8a25e810-ced6-4f23-880d-5f8c2f9881fe', 'type': 'access', 'user': {'username': 'alice', 'id': 1, 'perms': []}, 'refresh_iat': 1624227492}}

jwt_refresh_updated
-------------------

If the updating endpoint is available (as by the ``settings``) then when the updating of the refresh successfully happens this signal is sent. Example:

.. code-block::

  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_refresh_updated.connect(handler, sender='UpdateRefreshView')


.. code-block:: shell

  sender:  UpdateRefreshView
  kwargs:  {'signal': <django.dispatch.dispatcher.Signal object at 0x7f90ce66b340>, 'request': <WSGIRequest: POST '/api/token/refresh/update_refresh/'>, 'refresh_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624227763, 'exp': 1624314163, 'jti': '1eefc7bb-d124-407c-a9d8-cc5549a114a4', 'type': 'refresh', 'user': {'username': 'alice', 'id': 1, 'perms': []}}, 'access_claims': {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': 1624227763, 'exp': 1624257763, 'jti': '1eefc7bb-d124-407c-a9d8-cc5549a114a4', 'type': 'access', 'user': {'username': 'alice', 'id': 1, 'perms': []}, 'refresh_iat': 1624227763}}
