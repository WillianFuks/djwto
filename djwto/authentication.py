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
from functools import wraps
from typing import Any, Callable, Dict, List, Tuple, cast

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http.request import HttpRequest
from django.http.response import JsonResponse

import djwto.settings as settings
import djwto.tokens as tokens
from djwto.exceptions import JWTValidationError


class THttpRequest(HttpRequest):
    """
    Helper class to workaround mypy not recognizing attributes `token` and `payload`
    in `HttpRequest`.
    """
    payload: Dict[str, Any]
    token: str


WWWAUTHENTICATE = 'Bearer realm=api'


def jwt_passes_test(
    test_func: Callable[[THttpRequest], Tuple[bool, str]]
) -> Callable:
    """
    Function based on the original Django's `user_passes_test` but adapted to work with
    the jwt tokens instead.

    Args
    ----
      test_func: Callable[[Dict[str, Any]], bool]
          Function that returns `True` if tests succeeds and `False` otherwise. It
          receives the payload of the jwt token as input.

    Returns
    -------
      Callable
          Decorator function to receive the input `view_func` and process the request.
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def _wrapped_view(
            request: THttpRequest, *args: Any, **kwargs: Any
        ) -> JsonResponse:
            worked, error = test_func(request)
            if error:
                return JsonResponse({'error': error}, status=403)
            if worked:
                return view_func(request, *args, **kwargs)
            else:
                return JsonResponse({'error': 'Failed to validate token.'}, status=403)
        return _wrapped_view
    return decorator


def jwt_login_required(func: Callable) -> Callable:
    """
    Similar to the original Django's `login_required` but functioning on top of the jwt
    token as processed from the request. This function specifically enforces on views
    the requirement for the tokens been already created and validated in order for the
    dispatch to continue.

    Args
    ----
      func: Callable
          Refers to one of the verbs a view can have, such as `POST` or `GET`.

    Returns
    -------
      Callable
          Decorator that returns function to process view if and only if the requried
          jwt tokens for authentication are available in the income `request` object.
    """
    def test_func(request: THttpRequest) -> Tuple[bool, str]:
        try:
            token = get_raw_token_from_request(request)
            payload = tokens.decode_token(token)
            request.payload = payload
            request.token = token
            return ('username' and 'id') in payload.get('user', {}), ''
        except (JWTValidationError, ImproperlyConfigured) as err:
            return False, str(err)
    return jwt_passes_test(test_func)(func)


def jwt_perm_required(perms: List[str]) -> Callable:
    """
    Receives a list of permissions and only process the inner function if the jwt token
    available in the input request have the required permissions.
    """
    def process_func(func: Callable) -> Callable:
        """
        Similar to the original Django's `permission_required` but functioning on top of
        the jwt token as processed from the request. This function specifically enforces
        on views that the input token has a field inside of the claim `user` called
        `perms` containing the specified permission to process the input function.

        Args
        ----
          func: Callable
              Refers to one of the verbs a view can have, such as `POST` or `GET`.

        Returns
        -------
          Callable
              Decorator that returns function to process view if and only if the requried
              jwt tokens contains the necessary permissions.
        """
        def test_func(request: THttpRequest) -> Tuple[bool, str]:
            # It's supposed by default that `jwt_login_required` comes first. This
            # guarantees that `request.payload` will not be `None`
            if not getattr(request, 'payload', ''):
                return False, 'Login must happen before evaluating permissions.'
            payload = request.payload
            jwt_perms = payload.get('user', {}).get('perms')
            if jwt_perms:
                if not all([perm in jwt_perms for perm in perms]):
                    return False, 'Insufficient Permissions.'
                return True, ''
            return False, 'Invalid permissions for jwt token.'
        return jwt_passes_test(test_func)(func)
    return process_func


def jwt_is_refresh(view_func: Callable) -> Callable:
    """
    Some views only work with the refresh token. This decorator validates whether the
    input request has a refresh token or not, returning error response if the token is
    not found.

    Args
    ----
      view_func: Callable
          Refers to one of the verbs a view can have, such as `POST` or `GET`.

    Returns
    -------
      Callable
          Decorator that returns function to process view if and only if the requried
          jwt tokens for authentication are available in the income `request` object.
    """
    def test_func(request: THttpRequest) -> Tuple[bool, str]:
        # In this case token should be in Header AUTHORIZATION
        if settings.DJWTO_MODE == 'JSON':
            if request.payload.get('type') != 'refresh':
                return False, 'Refresh token was not sent in authorization header.'
            return True, ''
        path = settings.DJWTO_REFRESH_COOKIE_PATH
        if path not in request.path:
            return False, f'Refresh token is only sent in path: {path}'
        if request.method == 'POST' and request.POST.get('jwt_type') != 'refresh':
            return False, 'POST variable "jwt_type" must be equal to "refresh".'
        return True, ''
    return jwt_passes_test(test_func)(view_func)


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
    # cast to `User` type as `get_user` returns AbstractUser
    user = cast(User, form.get_user())
    return user


def jwt_authenticate(request: HttpRequest) -> Dict[str, Any]:
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
    token = get_raw_token_from_request(request)
    validated_token = tokens.decode_token(token)
    return validated_token


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
      JWTValidationError:
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
            if (
                type_ == 'refresh' and
                settings.DJWTO_REFRESH_COOKIE_PATH not in request.path
            ):
                raise JWTValidationError(
                    'Refresh cookie is only sent in path '
                    f'"/{settings.DJWTO_REFRESH_COOKIE_PATH}". Requested path was: '
                    f'{request.path}.'
                )
            raise JWTValidationError(f'Cookie "jwt_{type_}" cannot be empty.')
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
