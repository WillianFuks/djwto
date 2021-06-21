Protecting Views
================

jwt_login_required
------------------

djwto offers the decorator ``jwt_loging_required`` for guaranteeing a view to only be processed if the required and valid JWT token was sent in the request. Here's an example. Suppose again a regular Django project with the usual *testapp* with a view defined as:

.. code-block::

  import djwto.authentication as auth # type: ignore
  from django.views import View
  from django.utils.decorators import method_decorator
  from django.http.response import HttpResponse


  class ProtectedView(View):
      def dispatch(self, request, *args, **kwargs):
          return super().dispatch(request, *args, **kwargs)

      @method_decorator(auth.jwt_login_required)
      def get(self, request, *args, **kwargs):
          refresh_claims = request.payload
          print(refresh_claims)
          return HttpResponse('worked!')


Notice the decorator ``auth.jwt_login_required`` protecting the view. Now let's see what happens if we send a request without the JWT available:

.. code-block:: shell

  r = sess.get('https://localhost:8001/testapp/protect/')

  r.content
  b'{"error": "Cookie \\"jwt_access_token\\" cannot be empty."}'


If we properly login:

.. code-block:: shell

  r.content
  b'worked!'

jwt_perm_required
-----------------

djwto also offers the possibility of protecting views with permissions that should be available in the JWT token. Here's an example: decorate a view with the ``jwt_perm_required`` function like so:

.. code-block::

  class PermsProtectedView(View):
      def dispatch(self, request, *args, **kwargs):
          return super().dispatch(request, *args, **kwargs)

      @method_decorator(auth.jwt_login_required)
      @method_decorator(auth.jwt_perm_required(['perm1']))
      def get(self, request, *args, **kwargs):
          refresh_claims = request.payload
          print(refresh_claims)
          return HttpResponse('perms also worked!')

The function receives a list of permissions as input and only if the input JWT token contains those permissions is that the view will be processed.

Now, sending the request with a regular JWT token returns:

.. code-block:: shell

  r = sess.get('https://localhost:8001/testapp/perms_protect/')

  r.content
  b'{"error": "Invalid permissions for jwt token."}'

Suppose now that *Alice* has the permission ``perm1`` stored in the database. Here's the result then:

.. code-block:: shell

  r.content
  b'perms also worked!'

If you run these examples with settings ``DJWTO_MODE=TWO-COOKIES``, you'll be able to see what's inside the returned cookie, like so:

.. code-block:: shell

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": 1624269024, "iat": 1624239024, "iss": "iss", "jti": "0e9bfcdc-d684-47b5-9677-0cb5e5e88893", "refresh_iat": 1624239024, "sub": "sub", "type": "access", "user": {"email": "alice@djwto.com", "id": 1, "perms": ["perm1"], "username": "alice"}}'
