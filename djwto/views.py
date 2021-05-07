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


from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Callable

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.http.request import HttpRequest
from django.http.response import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.utils.decorators import method_decorator

import djwto.authentication as auth
import djwto.models as models
import djwto.tokens as tokens
from djwto.exceptions import JWTBlacklistError, JWTValidationError


HEADERS401 = {'WWW-Authenticate': auth.WWWAUTHENTICATE}


def identity(func: Callable) -> Callable:
    """
    Helper function to be used when `settings.CHECK_CSRF` is `False`; in this case the
    dispatch decorators should operate just as normally and therefore we return the
    function (or method) itself as if nothing really changed.

    Arguments
    ---------
      func: Callable
          Function to return directly. Usually this will be `post` methods defined in
          views.

    Returns
    -------
      func: Callable
          Same function as input, nothing changes when CSRF is not enabled.
    """
    return func


def _build_decorator(func: Callable) -> Callable:
    """
    If CSRF is enabled and there are cookies being saved then return the input `func`
    wrapped by the `method_decorator` function.

    Arguments
    ---------
      func: Callable
          Function to wrap and make it available for methods decorator. Usually will be
          either `ensure_csrf_cookie` or `csrf_protect`.

    Returns
    -------
      func: Callable
          Function decorated to operate with methods.
    """
    if settings.DJWTO_CSRF and settings.DJWTO_MODE in {'ONE-COOKIE', 'TWO-COOKIES'}:
        return method_decorator(func)
    return method_decorator(identity)


class GetTokensView(View):
    """
    Creates the JWT Token and stores then according to the specification in
    `settings.DJWTO_MODE`.
    """
    @_build_decorator(ensure_csrf_cookie)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        try:
            user = auth.user_authenticate(request)
        except ValidationError as err:
            return JsonResponse({'error': err.args[0]}, status=401,
                                headers=HEADERS401)

        try:
            refresh_claims = tokens.process_claims(user, request, args, kwargs)
            access_claims = tokens.get_access_claims_from_refresh(refresh_claims)

            refresh_token = tokens.encode_claims(refresh_claims)
            access_token = tokens.encode_claims(access_claims)

            return self._build_response(refresh_token,  access_token, access_claims)

        except ImproperlyConfigured:
            # As it's an internal error then don't return full error message to the
            # client. It should be handled internally by the server side.
            return JsonResponse({'error': 'Failed to process request.'}, status=500)

    def _build_response(
            self,
            refresh_token: str,
            access_token: str,
            access_claims: Dict[str, Any],
    ) -> JsonResponse:
        """
        djwto offers three main modes for returning a response: "JSON", "ONE-COOKIE" or
        "TWO-COOKIES". This method builds the http response in accordance to what
        `settings.DJWTO_MODE` specifies.

        For "JSON" option, the tokens as simply put into a dictionary and returned as a
        JSON response type. For "ONE-COOKIE", each token (refresh and access) is saved
        into a separate respective cookie.

        In "TWO-COOKIES" mode, the access token is divided in two partes:
        - "jwt_access_payload": contains the serialized value of the claims stored in an
        open Http Cookie so the front-end can read it.
        - "jwt_access_token": jwt token value, stored in a protected cookie for safety.

        The payload part is publicly available for reading by the client whereas the
        signature is saved as HttpOnly. This allows for the front-end to interact with
        the JWT content without running the risk of compromising the signature.

        Args
        ----
          refresh_token: str
              Token already encoded.
          access_token: str
          access_claims: Dict[str, Any]
              If `settings.DJWTO_MODE == 'TWO-COOKIES'` then it's expected the value of
              `access_claims` will be serialized in the cookie content. This allows for
              the front-end to have access to its values. The signature of the cookie is
              still separated and stored under `HttpOnly` and `Secure` conditions.

        Returns
        -------
          JsonResponse
              Returns tokens in accordance to `settings.DJWTO_MODE` value.
        """
        mode = settings.DJWTO_MODE
        if mode == 'JSON':
            return JsonResponse({'refresh': refresh_token, 'access': access_token})

        refresh_lifetime = settings.DJWTO_REFRESH_TOKEN_LIFETIME
        max_age_refresh = (
            int(refresh_lifetime.total_seconds()) if refresh_lifetime else None
        )

        access_lifetime = settings.DJWTO_ACCESS_TOKEN_LIFETIME
        max_age_access = (
            int(access_lifetime.total_seconds()) if access_lifetime else None
        )

        response = JsonResponse({})
        response.set_cookie(
            'jwt_refresh',
            refresh_token,
            max_age=max_age_refresh,
            httponly=True,
            secure=True,
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE
        )
        if mode == 'ONE-COOKIE':
            response.set_cookie(
                'jwt_access',
                access_token,
                max_age=max_age_access,
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            return response
        if mode == 'TWO-COOKIES':
            response.set_cookie(
                'jwt_access_payload',
                json.dumps(access_claims, sort_keys=True, cls=DjangoJSONEncoder),
                max_age=max_age_access,
                httponly=False,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            response.set_cookie(
                'jwt_access_token',
                access_token,
                max_age=max_age_access,
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            return response
        raise ImproperlyConfigured(
            'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
            f'Received "{mode}" instead.'
        )


class ValidateTokensView(View):
    """
    Extracts the jwt token from income `request` and assess if the token is valid.
    """
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        pass


class BlackListTokenView(View):
    """
    Extracts the jwt token from income `request` and adds it to the Blacklist table.
    The Blacklist functionality is only available if `settings.DJWTO_JTI_CLAIM` is `True`

    Only the refresh token can be blacklisted. After the operation, available cookies are
    deleted accordingly as well.
    """
    @_build_decorator(csrf_protect)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        return super().dispatch(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        if settings.DJWTO_REFRESH_COOKIE_PATH not in request.path:
            error_msg = (
                'Only the refresh token can be blacklisted. The URL endpoint for '
                'blacklisting must contain the value set in '
                '`settings.DJWTO_REFRESH_COOKIE_PATH`.'
            )
            return JsonResponse({'error': error_msg}, status=403)

        if not settings.DJWTO_JTI_CLAIM:
            error_msg = (
                'Value of `settings.DJWTO_JTI_CLAIM` must be `True` in order to use '
                'Blacklist.'
            )
            return JsonResponse({'error': error_msg}, status=403)

        type_ = request.POST.get('jwt_type')
        if not type_ or type_ != 'refresh':
            error_msg = 'Field "jwt_type=refresh" must be sent in request.'
            return JsonResponse({'error': error_msg}, status=403)

        try:
            token = auth.JWTAuthentication.get_raw_token_from_request(request)
            payload = auth.JWTAuthentication.validate_token(token)
        except JWTValidationError as err:
            return JsonResponse({'error': err.args[0]}, status=403)

        jti = payload.get('jti')
        if not jti:
            error_msg = (
                'No jti claim was available in the input token. The value is mandatory'
                'in order to use the Blacklist api.'
            )
            return JsonResponse({'error': error_msg}, status=403)

        # jti key is checked in case another token was created with the same jti but
        # different expire time (this should not happen so this checking works as a
        # protection against that.
        if models.JWTBlacklist.is_blacklisted(jti):
            error_msg = (
                'Input jti token is already blacklisted.'
            )
            return JsonResponse({'error': error_msg}, status=409)

        exp = payload.get('exp')
        if exp:
            exp = datetime.utcfromtimestamp(exp)

        models.JWTBlacklist.objects.get_or_create(
            jti=jti,
            token=token,
            expires=exp
        )
        return self._build_response()

    def _build_response(self) -> JsonResponse:
        """
        Returns a successfull message to the client and deletes remaining cookies.
        """
        response = JsonResponse({'message': 'Token successfully blacklisted.'},
                                status=409)
        response.delete_cookie('jwt_refresh')

        if settings.DJWTO_MODE == 'ONE-COOKIE':
            response.delete_cookie('jwt_access')

        if settings.DJWTO_MODE == 'TWO-COOKIES':
            response.delete_cookie('jwt_access_payload')
            response.delete_cookie('jwt_access_signature')
        return response
