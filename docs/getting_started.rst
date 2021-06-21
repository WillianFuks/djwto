Getting Started
===============

Installation
------------

Install djwto with pip:

.. code-block:: shell

  pip install djwto

Then add ``'djwto'`` to the list of ``INSTALLED_APPS`` in your *settings.py* file:

.. code-block::

    INSTALLED_APPS = [
        'django.contrib.auth',
        'django.contrib.contenttypes',
        ...
        'djwto'
    ]

Please refer to :ref:`settings` for more information on how to configure djwto.

For using the default urls offered by this package, simply add them to your ``urls.py`` file:

.. code-block::

  from django.contrib import admin
  from django.urls import path, include


  urlpatterns = [
    path('', include('djwto.urls')),
  ]

Please refer to :ref:`endpoints` for a detailed explanation of all endpoints available.

Requirements
------------

- Python (3.7, 3.8, 3.9)
- Django 3+

Overview
--------

djwto was designed to operate in 3 available modes:

- ``JSON``

  The JWT token is simply a string returned to the client. Example:

.. code-block::

  import requests


  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  r.json()
  {'refresh': 'eyJ0eXAiO.eyJpc3MiOiJ.QXq8sbgIEgT', 'access': 'eyJ0eXAiOi.eyJpc3MiOiJ.TtSnWdrhWuX'}

The *access*  token is equivalent to the *refresh* one but is short-lived. When it expires, it
needs to be recreated by using the latter.

Further authentication simply requires that one of the tokens be available in the
``AUTHORIZATION`` header of the request following the ``Bearer`` template.

- ``ONE-COOKIE``

The JWTs are saved into cookies:

.. code-block::

  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='DB6kR7o'), Cookie(name='jwt_access', value='eyJ0.eyJpc.kJsR'), Cookie(name='jwt_refresh', value='eyJ0e.eyJ.wWr')]>

- ``TWO-COOKIES``

  Also returns cookies but the *access* token is divided in two parts,
  one contains the base64 encoded JWT token that can be used seamlessly by the frontend
  and the second is the fully encoded JWT token used for the auth procedure:

.. code-block::

  import base64


  sess = requests.Session()
  r = sess.post('https://localhost:8001/login/',
                data={'username': 'alice', 'password': 'pass'})

  sess.cookies
  <RequestsCookieJar[Cookie(name='csrftoken', value='N1vJ9D'), Cookie(name='jwt_access_payload', value='eyJhdWQiO.ZXJuYW1lIj.FsaWN'), Cookie(name='jwt_access_token', value='eyJ0eXAi.OiJKV1QiLC.JhbGciOiJIU'), Cookie(name='jwt_refresh', value='eyJ0eXA.iOiJKV1Qi.LCJhbGc')]>

  base64.b64decode(sess.cookies['jwt_access_payload'])
  b'{"aud": "aud", "exp": "2021-06-18T02:32:55.144", "iat": "2021-06-17T18:12:55.144", "iss": "iss", "jti": "0b2d199d-f233-4203-bdab-693c03bca505", "refresh_iat": 1623953575, "sub": "sub", "type": "access", "user": {"id": 1, "perms": [], "username": "alice"}}'

Support
-------

If you find bugs or need help please open an issue on the offical `github <https://github.com/WillianFuks/djwto>`_ repository.

Contributions
-------------

This project heavily benefits with contributions from the community! If you want to contribute
you are more than welcome! Only thing we ask is to open an issue before implementing new
code so we can discuss details of the implementation before its development.
