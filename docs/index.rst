djwto
=====

Welcome to djwto's documentation!

djwto (reads *jot two*) is an alternative JWT authentication system built for Django
applications. It was designed to offer some new features for the auth layer, such as:

- Authentication can be either a *bearer token* or a *cookie*.
- Auth cookie can be split into two parts (that's the inspiration for the name of this lib).
  The first part contains the token itself, not encoded, and can be used by the frontend.
  The second part is the encoded token and is protected from JavaScript access (`httpOnly`),
  used by the backend in the auth process.
- CSRF protection by default.
- Extensible: several parts of the code can be customized.
- Full auth layer: views can be protected and authorized based solely on the JWT token.

Details of each point will be further explained in this doc.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started
   settings
   endpoints
   signals
   customization
   protect
