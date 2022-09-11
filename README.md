[![Build Status](https://github.com/WillianFuks/djwto/actions/workflows/run-tests.yml/badge.svg)](https://github.com/WillianFuks/djwto/actions)
[![Build Status](https://github.com/WillianFuks/djwto/actions/workflows/publish-to-pypi.yml/badge.svg)](https://github.com/WillianFuks/djwto/actions)
[![Coverage Status](https://codecov.io/gh/WillianFuks/djwto/branch/master/graph/badge.svg)](https://codecov.io/gh/WillianFuks/djwto/branch/master/) 
[![PyPI version](https://badge.fury.io/py/djwto.svg)](https://badge.fury.io/py/djwto) 
[![GitHub license](https://img.shields.io/github/license/WillianFuks/djwto.svg)](https://github.com/WillianFuks/djwto/blob/master/LICENSE)
[![Documentation Status](https://readthedocs.org/projects/djwto/badge/?version=latest)](https://djwto.readthedocs.io/en/latest/?badge=latest)
[![Pyversions](https://img.shields.io/pypi/pyversions/djwto.svg)](https://pypi.python.org/pypi/djwto)

![](https://raw.githubusercontent.com/WillianFuks/djwto/master/logo.png)

Welcome to **djwto**!

djwto ("*jot two*") is an alternative library offering support for JWT based authentication on top of the Django framework. Its main features are:

- Authentication either through a **Bearer** token or **Cookies**.
- **Access** token can be divided into two parts where one part is not encoded and can be used by the client (hence the lib name).
- **CSRF** protection by default.
- **Customizable**. Add your own code when you see fit.
- **Full Auth Layer**: protect your views by requiring the JWT tokens to be present in the income request. Also available for the permissions layer.

## Documentation

Complete [documentation](https://djwto.readthedocs.io/en/latest/?) is also available at ReadTheDocs.

## Installation

Install it through pip directly:

```sh
    pip install djwto
```

Then make it available in your `INSTALLED_APPS`:

```sh
    INSTALLED_APPS = [
        'django.contrib.auth',
        'django.contrib.contenttypes',
        ...
        'djwto'
    ]
```

And for using its defaults urls, add it to your `urls.py` project file:


```python
  from django.contrib import admin
  from django.urls import path, include


  urlpatterns = [
    path('', include('djwto.urls')),
  ]
```

## Requirements

- Python (3.7, 3.8, 3.9)
- Django 3+

## Overview

Contents:
- [Json](#json)
- [One-cookie](#one-cookie)
- [Two-cookies](#two-cookies)
- [Settings](#settings)
- [Endpoints](#endpoints)
- [Signals](#signals)
- [Customization](#customization)
- [Protecting Views](#protecting-views)
- [Contributing and Bugs](#contributing-and-bugs)

djwto offers 3 main ways to process the JWT tokens, which is defined by the settings `DJWTO_MODE`.  Despite of the mode running, the tokens are always returned as `acccess` and `refresh`.

The first is intended to be short-lived and used more often whereas the second lives longer and is only sent on a specific path as defined by the setting `DJWTO_REFRESH_COOKIE_PATH`. Its purpose, as the name implies, is to refresh and create a new *access* token.

Here's an overview of each mode available:

### JSON

In this setting the tokens are returned as a direct JSON response to the client. Here's an example using the `requests` library, running on a simple demo Django project:

```python
  import requests


  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  r.json()
  {'refresh': 'eyJ0eXAiO.eyJpc3MiOiJ.QXq8sbgIEgT', 'access': 'eyJ0eXAiOi.eyJpc3MiOiJ.TtSnWdrhWuX'}
```

In order to make further requests to the backend the client would have to grab the tokens and add them to the ``AUTHORIZATION`` header with the **Bearer** pattern.

### ONE-COOKIE

In this mode, the tokens are returned in Cookies. Here's an example:

```python
  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='DB6kR7o'), Cookie(name='jwt_access', value='eyJ0.eyJpc.kJsR'), Cookie(name='jwt_refresh', value='eyJ0e.eyJ.wWr')]>

```

Notice we have:
- `csrftoken`
- `jwt_access`
- `jwt_refresh`

The first must be sent on a `header` on views protected by CSRF and the last two are the ones used for the auth layer.

### TWO-COOKIES

Similar to `ONE-COOKIE` but this time the *access* token is divided in two pieces. Here's an example:

```python
  import base64


  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='N1vJ9D'), Cookie(name='jwt_access_payload', value='eyJhdWQiO.ZXJuYW1lIj.FsaWN'), Cookie(name='jwt_access_token', value='eyJ0eXAi.OiJKV1QiLC.JhbGciOiJIU'), Cookie(name='jwt_refresh', value='eyJ0eXA.iOiJKV1Qi.LCJhbGc')]>

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": "2021-06-18T02:32:55.144", "iat": "2021-06-17T18:12:55.144", "iss": "iss", "jti": "0b2d199d-f233-4203-bdab-693c03bca505", "refresh_iat": 1623953575, "sub": "sub", "type": "access", "user": {"id": 1, "perms": [], "username": "alice"}}'
```

Now we have the following cookies:

- `csrftoken`
- `jwt_access_payload`
- `jwt_access_token`
- `jwt_refresh`

Notice the access token now have two components: payload and the token itself. The payload is the original payload encoded in `base64` which can be used by the client receiving those cookies. The other part though is protected from javascript access and should only be used by the backend.

## Settings

Here's an overview of all settings available for djwto:

```python
DJWTO_ISS_CLAIM: Optional[str] = getattr(settings, 'DJWTO_ISS_CLAIM', None)
DJWTO_SUB_CLAIM: Optional[str] = getattr(settings, 'DJWTO_SUB_CLAIM', None)
DJWTO_AUD_CLAIM: Optional[Union[List[str], str]] = getattr(settings, 'DJWTO_AUD_CLAIM', None)

DJWTO_IAT_CLAIM: bool = getattr(settings, 'DJWTO_IAT_CLAIM', True)
DJWTO_JTI_CLAIM: bool = getattr(settings, 'DJWTO_JTI_CLAIM', True)

DJWTO_ALLOW_REFRESH_UPDATE: bool = getattr(settings, 'DJWTO_ALLOW_REFRESH_UPDATE', True)

DJWTO_ACCESS_TOKEN_LIFETIME = getattr(settings, 'DJWTO_ACCESS_TOKEN_LIFETIME', timedelta(minutes=5))
DJWTO_REFRESH_TOKEN_LIFETIME = getattr(settings, 'DJWTO_REFRESH_TOKEN_LIFETIME', timedelta(days=1))
DJWTO_NBF_LIFETIME: Optional[timedelta] = getattr(settings, 'DJWTO_NBF_LIFETIME', timedelta(minutes=0))

DJWTO_SIGNING_KEY: str = getattr(settings, 'DJWTO_SIGNING_KEY', os.environ['DJWTO_SIGNING_KEY'])

# Only set if Algorithm uses asymetrical signing.
DJWTO_VERIFYING_KEY: Optional[str] = getattr(settings, 'DJWTO_VERIFYING_KEY', None)

DJWTO_ALGORITHM: str = getattr(settings, 'DJWTO_ALGORITHM', 'HS256')

DJWTO_MODE: Literal['JSON', 'ONE-COOKIE', 'TWO-COOKIES'] = getattr(settings, 'DJWTO_MODE', 'JSON')

DJWTO_REFRESH_COOKIE_PATH: str = getattr(settings, 'DJWTO_REFRESH_COOKIE_PATH', 'api/token/refresh')

DJWTO_SAME_SITE: str = getattr(settings, 'DJWTO_SAME_SITE', 'Lax')
DJWTO_DOMAIN: Optional[str] = getattr(settings, 'DJWTO_DOMAIN', None)

DJWTO_CSRF: bool = getattr(settings, 'DJWTO_CSRF', True)
```

For a thorough view of each please refer to the official [docs](https://djwto.readthedocs.io/en/latest/?).

## Endpoints

Here's an overview of each endpoint offered by djwto and how to use them. For each endpoint, if something goes wrong then a key `error` should be available in the response and its value should be an explanation for the event.


### `/login/`

Simply POST to this endpoint with data containing the user `username` and their input `password`, the return response, if valid, should contain the newly created JWTs for the client.

The return type depends on which mode djwto is running; here's an example on ``DJWTO_MODE=JSON`` mode making use of the [requests](https://docs.python-requests.org/en/master/>) library:

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  r.json()
  {'refresh': 'eyJ0eXAiO.eyJpc3MiOiJ.QXq8sbgIEgT', 'access': 'eyJ0eXAiOi.eyJpc3MiOiJ.TtSnWdrhWuX'}
```

### `/validate/`

Sometimes the frontend may want to confirm whether a given token is still valid or not; that's the purpose of this endpoint. Supposing that the *login* process has already taken place, here's an example of *access* token validation on mode ``JSON``:

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["access"]}'})

  r = sess.post('https://localhost:8001/validate_access/')

  print(r.json())
  {'msg': 'Token is valid'}
```

Here's an example for `TWO-COOKIES:`

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.post('https://localhost:8001/login/',
            data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/validate_access/',
                headers={'REFERER': 'https://localhost:8001'})
```

Notice that the `CSRF` token is being sent in the header as `X-CSRFToken` and also there's a `REFERER` value indicating from where the client is coming (this is mandatory as by Django's built-in csrf techniques protection).

In order to validate the *refresh*, here's an example:

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  sess.post('https://localhost:8001/login/',
            data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'X-CSRFToken': sess.cookies['csrftoken']})

  r = sess.post('https://localhost:8001/api/token/refresh/validate_refresh/',
                headers={'REFERER': 'https://localhost:8001'},
                data={'jwt_type': 'refresh'})
```

Notice that the `POST` must send the data `jwt_type='refresh'` to specify for the backend which token to use.

### `/refresh_access/`

The *access* token is designed to be short-lived, that is, it grants access for clients for a brief period of time before it goes expired. The reasoning is that after it expires the API has a chance to validate whether the client can continue receiving new tokens or not (so in case the client logged out or was blacklisted for some reason they'd lose access thereafter).

When the token expires, a new one can be obtained by posting the refresh token to this endpoint. Here's an example for ``JSON`` mode:

```python
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
```

### `/update_refresh/`

At some scenarios it may be interesting for the JWT auth process to also be able to update the *refresh* token. This may occur for instance in an eCommerce environment when the customer is finishing the purchase process and may get blocked due expired token (which is highly undesirable). In order to allow this feature to be available, set ``settings.DJWTO_ALLOW_REFRESH_UPDATE`` to ``True``. Here's an example for ``JSON`` mode:

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["refresh"]}'})

  r = sess.post('https://localhost:8001/api/token/refresh/update_refresh/')
  print(r.json())
  {"refresh": '...', "access": '...'}
```

### `/logout/`

When logging a user out, if ``JTI`` is available then the tokens will be blacklisted. In either case, the tokens are deleted (both *access* and *refresh*). The request ``path`` must contain ``settings.DJWTO_REFRESH_COOKIE_PATH``. Here's an example for ``JSON`` mode:

```python
  import requests


  sess = requests.Session()
  sess.verify = False  # For testing locally
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})
  sess.headers.update({'AUTHORIZATION': f'Bearer {r.json()["refresh"]}'})

  r = sess.post('https://localhost:8001/api/token/refresh/logout/')
  print(r.content)
  b'{"msg": "Token successfully blacklisted."}'
```

For either `ONE-COOKIE` or `TWO-COOKIES`:

```python
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
```

Notice that the verb ``DELETE`` is also available with removes the cookies from the response. This option only works on for the cookie-based settings.

If after blacklisting a token a request is sent for updating either *access* or *refresh*, the process should fail:

```python
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
```

## Signals

djwto offers by default a set of signals that you can use in your projects for tracking down when certain events take place. In order to demonstrate how it works, consider a regular Django project created with an app called ``testapp``.

Here's a list of all available signals offered by the package:

### `/jwt_logged_in/`

The signal is triggered when a successfull loggin happens. Here's how to connect it:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_logged_in.connect(
          handler,
          sender='GetTokensView'
      )
```

On each successfull login the new function `handler` will process with appropriate input arguments.


### `/jwt_login_fail/`

The signal is triggered when a loggin fails by any reason. Here's how to connect it:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_login_fail.connect(handler, sender='GetTokensView')
```

### `/jwt_blacklisted/`

The signal is sent when a token is successfully blacklisted:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_blacklisted.connect(handler, sender='BlackListTokenView')
```

### `/jwt_token_validated/`

The signal is sent each time a validation request is processed:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_token_validated.connect(handler, sender='ValidateTokensView')
```

### `/jwt_access_refreshed/`

The signal is sent when the *access* token is successfully refreshed:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_access_refreshed.connect(handler, sender='RefreshAccessView')
```

### `/jwt_refresh_updated/`

If the updating endpoint is available (as by the ``settings``) then when the updating of the refresh successfully happens this signal is sent. Example:

```python
  def ready(self):
      import djwto.signals as signals

      def handler(sender, **kwargs):
          print('sender: ', sender)
          print('kwargs: ', kwargs)

      signals.jwt_refresh_updated.connect(handler, sender='UpdateRefreshView')
```

## Customization

djwto offers the possibility for the client to customize how parts of the code should be processed, replacing the original logic. Let's suppose a regular Django project with an app called *testapp*.

It's possible to specify customizations for djwto when the app is [ready](https://docs.djangoproject.com/en/3.2/ref/applications/#django.apps.AppConfig.ready>). For instance, if your project requires to also bring the customer's email when the JWT creation is running, here's one way of doing it:

```python
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
```

Running the loggin process for ``TWO-COOKIES``, we get now:

```python
  import requests
  import base64


  sess = requests.Session()
  sess.verify = False  # For testing locally

  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": 1624259339, "iat": 1624229339, "iss": "iss", "jti": "900f4f1a-3e0f-4843-9997-9fd8d032684e", "refresh_iat": 1624229339, "sub": "sub", "type": "access", "user": {"email": "alice@djwto.com", "id": 1, "perms": [], "username": "alice"}}'
```

Now the `user` key retrieves the user email as well.

Feel free to customize the code as you see fit.

## Protecting Views

djwto offers decorators that can be used on views in order to add the authentication layer protection. There are two functions for doing so:

### `jwt_login_required`

djwto offers the decorator ``jwt_loging_required`` for guaranteeing a view to only be processed if the required and valid JWT token was sent in the request. Here's an example. Suppose again a regular Django project with the usual *testapp* with a view defined as:

```python
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
```

Notice the decorator ``auth.jwt_login_required`` protecting the view. Now let's see what happens if we send a request without the JWT available:

```python
  r = sess.get('https://localhost:8001/testapp/protect/')

  r.content
  b'{"error": "Cookie \\"jwt_access_token\\" cannot be empty."}'
```

If we properly login:

```python
  r.content
  b'worked!'
```

### `jwt_perm_required`

djwto also offers the possibility of protecting views with permissions that should be available in the JWT token. Here's an example: decorate a view with the ``jwt_perm_required`` function like so:

```python
  class PermsProtectedView(View):
      def dispatch(self, request, *args, **kwargs):
          return super().dispatch(request, *args, **kwargs)

      @method_decorator(auth.jwt_login_required)
      @method_decorator(auth.jwt_perm_required(['perm1']))
      def get(self, request, *args, **kwargs):
          refresh_claims = request.payload
          print(refresh_claims)
          return HttpResponse('perms also worked!')
```

The function receives a list of permissions as input and only if the input JWT token contains those permissions is that the view will be processed.

Now, sending the request with a regular JWT token returns:

```python
  r = sess.get('https://localhost:8001/testapp/perms_protect/')

  r.content
  b'{"error": "Invalid permissions for jwt token."}'
```

Suppose now that *Alice* has the permission ``perm1`` stored in the database. Here's the result then:

```python
  r.content
  b'perms also worked!'
```

If you run these examples with settings ``DJWTO_MODE=TWO-COOKIES``, you'll be able to see what's inside the returned cookie, like so:

```python
  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": 1624269024, "iat": 1624239024, "iss": "iss", "jti": "0e9bfcdc-d684-47b5-9677-0cb5e5e88893", "refresh_iat": 1624239024, "sub": "sub", "type": "access", "user": {"email": "alice@djwto.com", "id": 1, "perms": ["perm1"], "username": "alice"}}'
```

## Contributing and Bugs

Contributions are very welcome! If you want to send a PR please consider first discussing your implementation on an issue.

Also, if you find bugs (this is still an alpha project!) please let us know by also opening an issue on the official repository.
