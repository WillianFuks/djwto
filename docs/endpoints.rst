.. _endpoints:

Endpoints
=========

/login/
-------

Simply POST to this endpoint with data containing the user `username` and their input `password`. The return type depends on which mode djwto is running.

Here's an example on ``DJWTO_MODE=JSON`` mode, using the `requests <https://docs.python-requests.org/en/master/>`_ library:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  r.json()
  {'refresh': 'eyJ0eXAiO.eyJpc3MiOiJ.QXq8sbgIEgT', 'access': 'eyJ0eXAiOi.eyJpc3MiOiJ.TtSnWdrhWuX'}

The return is simply a JSON containing both *access* and *refresh* tokens.

Here's the return when ``DJWTO_MODE=ONE-COOKIE``:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='DB6kR7o'), Cookie(name='jwt_access', value='eyJ0.eyJpc.kJsR'), Cookie(name='jwt_refresh', value='eyJ0e.eyJ.wWr')]>

Notice that both *access* and *refresh* tokens are now available in the response cookie attribute. Also, the ``csrf`` token that was set. If ``DJWTO_CSRF=True`` then djwto's views will be protected against `CSRF <https://owasp.org/www-community/attacks/csrf>`_ attacks which means the frontend client must send this value in a ``CSRFToken`` header on POSTs requests.

Here's the return when ``DJWTO_MODE=TWO-COOKIES``:

.. code-block::

  import requests
  import base64


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='N1vJ9D'), Cookie(name='jwt_access_payload', value='eyJhdWQiO.ZXJuYW1lIj.FsaWN', rest={'HttpOnly': None, 'SameSite': 'Lax'}), Cookie(name='jwt_access_token', value='eyJ0eXAi.OiJKV1QiLC.JhbGciOiJIU'), Cookie(name='jwt_refresh', value='eyJ0eXA.iOiJKV1Qi.LCJhbGc')]>

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": "2021-06-18T02:32:55.144", "iat": "2021-06-17T18:12:55.144", "iss": "iss", "jti": "0b2d199d-f233-4203-bdab-693c03bca505", "refresh_iat": 1623953575, "sub": "sub", "type": "access", "user": {"id": 1, "perms": [], "username": "alice"}}'

It's similar to before but one of the *access* tokens is a ``base64`` encoded value. If we decode it, then we have access to the complete JSON that defines the token. The signature remains protected against Javascript access by being stored on other *HttpOnly* cookies.

/validate/
----------

Sometimes the frontend may want to confirm whether a given token is still valid or not; that's the purpose of this endpoint. Supposing that the *login* process has already taken place, here's an example of token validation on mode ``JSON``:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["access"]}'})

  r = sess.post('https://localhost:8001/validate_access/')

  print(r.json())
  {'msg': 'Token is valid'}

If the sent token is invalid somehow, the return response will contain an explanation for the cause of error in a key called 'error':

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()}'})

  r = sess.post('https://localhost:8001/validate_access/')

  print(r.json())
  {'error': "Invalid header string: 'utf-8' codec can't decode byte 0xad in position 0: invalid start byte"}

``ONE-COOKIE`` and ``TWO-COOKIES`` mode:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.post('https://localhost:8001/login/',
            data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/validate_access/',
                headers={'REFERER': 'https://localhost:8001'})

Notice the requirement to send in *headers* the value of ``REFERER`` as otherwise the CSRF token validation will fail (this happens thanks to HTTPS being set).

For validating the refresh tokens, the path request must contain the refresh path as defined in ``settings.DJWTO_REFRESH_COOKIE_PATH``. Here's an example:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.post('https://localhost:8001/login/',
            data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/api/token/refresh/validate_refresh/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})


The path ``api/token/refresh/`` is associated to the path in the refresh token and therefore only in this scenario the cookie will be sent. Also, notice that the API expects to receive as input data the field ``jwt_type`` with value *'refresh'* so it knows which cookie to validate (this value defaults to *'access'* that's why it's not necessary otherwise).

/refresh_access/
----------------

The *access* token is designed to be short-lived, that is, it grants access for clients for a brief period of time before it goes expired. The reasoning is that after it expires the API has a chance to validate whether the client can continue receiving new tokens or not (so in case the client logged out or was blacklisted for some reason they'd lose access thereafter).

When the token expires, a new one can be obtained by posting the refresh token to this endpoint. Here's an example for ``JSON`` mode:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["refresh"]}'})

  r = sess.post('https://localhost:8001/api/token/refresh/refresh_access/',
                headers={'REFERER': 'https://localhost:8001'})

  print(r.json())
  {"refresh": ..., "access": ...}

And for ``ONE-COOKIE`` (``TWO-COOKIES`` has a similar response):

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/api/token/refresh/refresh_access/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})

  print(r.content)
  b'{"msg": "Access token successfully refreshed."}'

  print(sess.cookies)
  <RequestsCookieJar[Cookie(name='csrftoken', value='Ti3rbJUrep'), Cookie(name='jwt_access', value='eyJ0eX.AiOiJK.V1Qi'), Cookie(name='jwt_refresh', value='eyJ0eXA.iOiJKV.1QiLC, path='/api/token/refresh')]>


/update_refresh/
----------------

At some scenarios it may be interesting for the JWT auth process to also be able to update the *refresh* token. This may occur for instance in an eCommerce environment when the customer is finishing the purchase process and may get blocked due expired token (which is highly undesirable). In order to allow this feature to be available, set ``settings.DJWTO_ALLOW_REFRESH_UPDATE`` to ``True``. Here's an example for ``JSON`` mode:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["refresh"]}'})

  r = sess.post('https://localhost:8001/api/token/refresh/update_refresh/')
  print(r.json())
  {"refresh": '...', "access": '...'}

``ONE-COOKIE`` and ``TWO-COOKIES`` are similar:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/api/token/refresh/update_refresh/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})

  print(sess.cookies)
  <RequestsCookieJar[Cookie(name='csrftoken', value='Ti3rbJUrep'), Cookie(name='jwt_access', value='eyJ0eX.AiOiJK.V1Qi'), Cookie(name='jwt_refresh', value='eyJ0eXA.iOiJKV.1QiLC, path='/api/token/refresh')]>

.. _blacklist:

/logout/
--------

When logging a user out, if ``JTI`` is available then the tokens will be blacklisted, i.e., they won't be considered valid anymore despite its time expectancy still being valid. In either case, the tokens are deleted (both *access* and *refresh*).

The request ``path`` must contain ``settings.DJWTO_REFRESH_COOKIE_PATH``. Here's an example for ``JSON`` mode:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["refresh"]}'})

  r = sess.post('https://localhost:8001/api/token/refresh/logout/')
  print(r.content)
  b'{"msg": "Token successfully blacklisted."}'


For ``ONE-COOKIE`` and ``TWO-COOKIES``:

.. code-block::

  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})
  r = sess.post('https://localhost:8001/api/token/refresh/logout/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})

  print(r.content)
  b'{"msg": "Token successfully blacklisted."}'

  r = sess.delete('https://localhost:8001/api/token/refresh/logout/',
                  headers={'REFERER': 'https://localhost:8001'},
                  data={'jwt_type': 'refresh'})

  print(r.content)
  b'{"msg": "Tokens successfully deleted."}'

Notice that the verb ``DELETE`` is also available with removes the cookies from the response. This option only works on for the cookie-based settings.

If after blacklisting a token a request is sent for updating either *access* or *refresh*, the process should fail:

.. code-block::

  r = sess.post('https://localhost:8001/api/token/refresh/update_refresh/',
                headers={'REFERER':'https://localhost:8001'},
                data={'jwt_type': 'refresh'})

  print(r.content)
  b'{"error": "Can\'t update refresh token."}'

  r = sess.post('https://localhost:8001/api/token/refresh/refresh_access/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})

  print(r.content)
  b'{"error": "Can\'t update access token."}'
