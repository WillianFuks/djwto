# MIT License
#
# Copyright (c) 2021 willfuks
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import json
import jwt as pyjwt
from typing import Any, Dict, Optional, Tuple, TypeVar, List, Union
from typing_extensions import Literal

from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.http.request import HttpRequest
from django.core.exceptions import ImproperlyConfigured, ValidationError

from djwto.exceptions import JWTValidationError


WWWAUTHENTICATE = 'Bearer realm=api'


def user_authenticate(request: HttpRequest) -> User:
    """
    Default method used for authenticating users; uses authentication layer as offered by
    Django.

    Args
    ----
      request: HttpRequest
          Request object as received by the web server processor (either WSGI or ASGI),
          expected to contain the field `data` filled with user name and password.

    Returns
    -------
      User
          If user successfully authenticate then returns their correspondent object from
          Django's default `User` model.

    Raises
    ------
      ValidationError: If validation of `form` fails.
    """
    form = AuthenticationForm(data=request.POST)
    form.is_valid()
    if form.errors:
        raise ValidationError(json.dumps(dict(form.errors)))
    return form.get_user()


class JWTAuthentication:
    def authenticate(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract token expected to be sent in input `request` and assess its validity. If
        still valid, returns general information available in the payload. Notice that
        in djwto package no request to the database is performed, that is, the entire
        validation process is based solely on whether the input token is a valid one or
        not. This approach follows precisely what JWT tokens were designed for.

        Args
        ----
          request: HttpRequest
              Input request processed from WSGI (or ASGI) server.

        Returns
        -------
          validated_token: Dict[str, Any]
              JWT token after validation process.

        Raises
        ------
          JWTValidationError: If input token is invalid.
        """
        token = self.get_raw_token_from_request(request)
        validated_token = self.validate_token(token)
        return validated_token

    @staticmethod
    def validate_token(token: str) -> Dict[Any, Any]:
        """
        Validates if input token (in the form of 'abc.def.ghi') is a valid JWT token. The
        token is considered valid if the HMAC of the payload is equal to the signature,
        as well as the expiration time is still bigger than current date or the field
        'nbf' is lower. If either 'exp' nor 'nbf' are available then skip those tests.

        Arguments
        ---------
          token: str
              JWT as extracted from request.

        Returns
        -------
          Tuple[Dict[Any, Any]
              If validated, returns the token payload in dict format.
        """
        sign_key = settings.DJWTO_SIGNING_KEY
        ver_key = settings.DJWTO_VERIFYING_KEY
        alg = [settings.DJWTO_ALGORITHM]
        iss = settings.DJWTO_ISS_CLAIM
        sub = settings.DJWTO_SUB_CLAIM
        aud = settings.DJWTO_AUD_CLAIM
        iat_flag = settings.DJWTO_IAT_CLAIM
        jti_flag = settings.DJWTO_JTI_CLAIM

        kwargs: Dict[str, Any] = {}
        required: List[str] = []

        def _update(name: str, value: Any) -> None:
            if value:
                kwargs[name] = value
                required.append(name[:3])

        _update('issuer', iss)
        _update('subject', sub)
        _update('audience', aud)
        _update('iat', iat_flag)
        _update('jti', jti_flag)

        try:
            payload = pyjwt.decode(token, ver_key if ver_key else sign_key, alg,
                                   options={'require': required}, **kwargs)
        except (
            pyjwt.ExpiredSignatureError,
            pyjwt.ImmatureSignatureError,
            pyjwt.MissingRequiredClaimError,
            pyjwt.DecodeError,
            pyjwt.InvalidTokenError
        ) as err:
            raise JWTValidationError(str(err))
        return payload

    @staticmethod
    def get_raw_token_from_request(request: HttpRequest) -> str:
        """
        Returns string as encoded by pyJWT library from request. Its storage can be in
        three different places according to `settings.DJWTO_MODE`:
          - 'JSON': the token is expected to be found in the `HTTP_AUTHORIZATION` header
            with value like "Authorization: Bearer abc.def.ghi".
          - 'ONE-COOKIE': the access token is expected to be found in a cookie named
            'jwt_access'.
          - 'TWO-COOKIES': the token is divided into two cookies, one called
            'jwt_access_payload' which contains the header and payload of the token and
            'jwt_access_signature' containing the signature to validate the payload.

        `request` may contain a data field named 'jwt_type' which is either 'access'
        (default) or 'refresh'. This value sets which token cookie to retrieve and is
        only valid if mode type also sets cookies.

        Arguments
        ---------
          request: HttpRequest
              Input request from WSGI (or ASGI) server.

        Returns
        -------
          str
              JWT token in the format abc.def.ghi

        Raises
        ------
          ValidationError:
              If token is not in header.
              If token is invalid.
              If token is empty.
              If cookies are not available.
          ImproperlyConfigured:
              If `settings.DJWTO_MODE` has invalid value.
        """
        if settings.DJWTO_MODE == 'JSON':
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if not auth_header:
                raise JWTValidationError(
                    'Token not found in "HTTP_AUTHORIZATION" header.'
                )
            token = auth_header.split('Bearer ')[-1]
            # Either token or the string 'Bearer ' are not available
            if not token or len(token) == len(auth_header):
                raise JWTValidationError(
                    'Value in HTTP_AUTHORIZATION header is not valid.'
                )
            return token
        # Defaults to 'access' to make it easier on the front-end calls
        type_ = request.POST.get('jwt_type', 'access')
        if type_ not in {'access', 'refresh'}:
            raise JWTValidationError(
                'Input data "jwt_type" must be either "access" or "refresh".'
                f' Got "{type_}" instead.'
            )
        if settings.DJWTO_MODE == 'ONE-COOKIE' or type_ == 'refresh':
            token = request.COOKIES.get(f'jwt_{type_}', '')
            if not token:
                raise JWTValidationError('Cookie "jwt_access" cannot be empty.')
            return token
        # If it made until here then only option is to retrieve access token
        if settings.DJWTO_MODE == 'TWO-COOKIES':
            token = request.COOKIES.get('jwt_access_token')
            if not token:
                raise JWTValidationError(
                    'Cookie "jwt_access_token" cannot be empty.'
                )
            return token
        raise ImproperlyConfigured(
            'Value of `settings.DJWTO_MODE` is invalid. Expected either "JSON", '
            f'"ONE-COOKIE" or "TWO-COOKIES". Received "{settings.DJWTO_MODE}" instead.'
        )
