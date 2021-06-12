Getting Started
===============

Introduction
------------

**djwto** was designed to operate in 3 available modes:

- ``'JSON'``: The JWT token generated after successfull login is simply a string token
  returned to the client. Further authentication requires the ``AUTHORIZATION`` header
  to be set with the value of ``Bearer (token)``.
- ``'ONE-COOKIE'``: The JWT returned will be set into the ``ACCESS TOKEN`` and ``REFRESH_TOKEN``.
  The first is short-lived and after it expires the *refresh* token must be used to obtain
  a new *access*. The *refresh* token is only sent for the specified ``DJWTO_REFRESH_COOKIE_PATH``
  according to the file settings.py.
- ``'TWO-COOKIES'``: Similar to *ONE-COOKIE* but the access token is divided in two parts,
  one part contains the raw JWT token that can be used seamlessly by the frontend and the
  second part is the full encoded JWT token used for the auth procedure.



Installation
------------

Install **djwto** with pip:

  pip install djwto

Then add ``'djwto'`` to the list of ``INSTALLED_APPS`` in your *settings.py* file:

.. code-block::

    INSTALLED_APPS = [
        'django.contrib.auth',
        'django.contrib.contenttypes',
        ...
        'djwto'
    ]

Please refer to :ref:`settings` for more information on how to fully customize **djwto**.

Requirements
------------

- Python (3.7, 3.8, 3.9)
- Django 3+

Support
-------

If you find bugs or need help please open an issue on the offical `github <https://github.com/WillianFuks/djwto>`_ repository.

Contributions
-------------

This project heavily benefits with contributions from the community! If you want to contribute
you are more than welcome! Only thing we ask is to open an issue before implementing new
code so we can discuss details of the implementation before its development.
