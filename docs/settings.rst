.. _settings:

Settings
========

Here is an example of all the options available for setting how **djwto** runs by default:

.. code-block::

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


``DJWTO_ISS_CLAIM``
-------------------

Sets the *Issuer* claim in the JWT token, as defined in the original `RFC <https://datatracker.ietf.org/doc/html/rfc7519>`_. This value is optional.

``DJWTO_SUB_CLAIM``
-------------------

Sets the *Subject* claim. This value is optional as per definition.

``DJWTO_AUD_CLAIM``
-------------------

Sets the *Audience* claim. This value can be either a string or a list of strings. It's also optional.

``DJWTO_IAT_CLAIM``
-------------------

Boolean that indicates whether to save the *IAT* claim or not. Defaults to `True`.

``DJWTO_JTI_CLAIM``
-------------------

Boolean that indicates whether to save a *JTI* claim or not. The identifier is unique and must be available in order to use the :ref:`blacklist <blacklist>` app. This value is optional.


``DJWTO_ACCESS_TOKEN_LIFETIME``
-------------------------------

Python ``timedelta`` object that indicates for how long the access token should be valid. This value is optional and in case it's not set then the token is considered to be always valid.


``DJWTO_REFRESH_TOKEN_LIFETIME``
--------------------------------

Similar to the previous item but related to the *refresh* token.

``DJWTO_NBF_LIFETIME``
----------------------

Sets the NBF (Not Before) claim. It's expressed in ``timedelta`` object and the issued tokens won't be valid until the time specified in this field has passed. This value is optional.

``DJWTO_SIGNING_KEY``
---------------------

Secret key used for hashing the tokens. By default it expects to find its value in an environment variable called "DJWTO_SIGNING_KEY".

``DJWTO_VERIFYING_KEY``
-----------------------

If using an asymetrical cryptographic algorithm this field should contain the private key. When using a symmetrical algorithm, leave this field empty.

``DJWTO_ALGORITHM``
-------------------

Cryptographic algorithm to use for hashing the tokens. Please refer to the oficial `PyJWT <https://pyjwt.readthedocs.io/en/stable/algorithms.html>`_ docs for a list of available algorithms.

``DJWTO_MODE``
--------------

Sets how djwto should process the tokens. It can be one of the 3 following values:

- ``JSON``: return the tokens (access and refresh) as a json value. For further authentication such tokens should appear in the `AUTHORIZATION` header with the `Bearer` template.
- ``ONE-COOKIE``: Tokens are set in cookies.
- ``TWO-COOKIES``: Also sets cookies but this time the access token is divided in two parts, one regular token and another part containing a base64 encoded representation of the token that can be read and used by the client with access to the token (the token itself is decoded so its claims can be used while the signature remains a secret).

``DJWTO_REFRESH_COOKIE_PATH``
-----------------------------

Sets the ``path`` for the refresh cookie. This is used to increase security of the system by sending the *refresh* token only on specific endpoints.

``DJWTO_SAME_SITE``
-------------------

Sets ``same_site`` field of the tokens cookies. Default value is ``'LAX'``.

``DJWTO_DOMAIN``
-------------------

Sets the domain of the cookies returned to the client. This is useful when working on cross-domain scenarios. For instance, suppose the frontend is running at `web.example.com` and the Django backend where `djwto` is installed is at `api.example.com`. Without setting a proper domain the cookies would be unreachable at the front. But choosing ``DJWTO_DOMAIN = 'example.com'`` would suffice for the front to be able to read the cookies.

``DJWTO_CSRF``
--------------

Boolean that sets whether to protect djwto views with CSRF or not. Defaults to ``True``.
