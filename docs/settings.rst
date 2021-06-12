.. _settings:

Settings
========

Here is an example of all the options available for specifying how **djwto** operates:

.. code-block::

    DJWTO_ISS_CLAIM = 'iss'
    DJWTO_SUB_CLAIM = 'sub'
    DJWTO_AUD_CLAIM = 'aud'
    DJWTO_IAT_CLAIM = True
    DJWTO_JTI_CLAIM = True

    DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(minutes=5)
    DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(days=1)
    DJWTO_NBF_LIFETIME = timedelta(minutes=1)
    DJWTO_SIGNING_KEY = 'test key'

    # Only set if Algorithm uses asymetrical signing.
    DJWTO_VERIFYING_KEY: Optional[str] = None
    DJWTO_ALGORITHM = 'HS256'
    DJWTO_MODE = 'JSON'
    DJWTO_REFRESH_COOKIE_PATH = '/api/token/refresh'
    DJWTO_SAME_SITE = 'Lax'
    DJWTO_CSRF = True
    DJWTO_ALLOW_REFRESH_UPDATE = True
    SECRET_KEY = 'key'
