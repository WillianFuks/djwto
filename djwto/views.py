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

import base64
import json
from calendar import timegm
from datetime import datetime
from typing import Any, Callable, Dict

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.http.request import HttpRequest
from django.http.response import HttpResponseBase, JsonResponse
from django.middleware.csrf import rotate_token
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import (csrf_exempt, csrf_protect,
                                          ensure_csrf_cookie)

import djwto.authentication as auth
import djwto.models as models
import djwto.settings as settings
import djwto.signals as signals
import djwto.tokens as tokens
from djwto.exceptions import JWTValidationError

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


def build_tokens_response(
    refresh_claims: Dict[str, Any],
    access_claims: Dict[str, Any],
    msg: str = None
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
      refresh_claims: Dict[str, Any]
          Token already encoded.
      access_claims: Dict[str, Any]
          If `settings.DJWTO_MODE == 'TWO-COOKIES'` then it's expected the value of
          `access_claims` will be serialized in the cookie content. This allows for
          the front-end to have access to its values. The jwt token cookie is still
          separated and stored under `HttpOnly` and `Secure` conditions.
      msg: str
          Message to return in JSON response to the client.

    Returns
    -------
      JsonResponse
          Returns tokens in accordance to `settings.DJWTO_MODE` value.
    """
    refresh_token = tokens.encode_claims(refresh_claims)
    access_token = tokens.encode_claims(access_claims)

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

    response = JsonResponse({'msg': msg})
    response.set_cookie(
        'jwt_refresh',
        refresh_token,
        max_age=max_age_refresh,
        httponly=True,
        secure=True,
        path=f'/{settings.DJWTO_REFRESH_COOKIE_PATH}',
        samesite=settings.DJWTO_SAME_SITE,
        domain=settings.DJWTO_DOMAIN
    )
    if mode == 'ONE-COOKIE':
        response.set_cookie(
            'jwt_access',
            access_token,
            max_age=max_age_access,
            httponly=True,
            secure=True,
            samesite=settings.DJWTO_SAME_SITE,
            domain=settings.DJWTO_DOMAIN
        )
        return response
    if mode == 'TWO-COOKIES':
        response.set_cookie(
            'jwt_access_payload',
            base64.b64encode(
                json.dumps(access_claims, sort_keys=True,
                           cls=DjangoJSONEncoder).encode(),
            ).decode(),
            max_age=max_age_access,
            httponly=False,
            secure=True,
            samesite=settings.DJWTO_SAME_SITE,
            domain=settings.DJWTO_DOMAIN
        )
        response.set_cookie(
            'jwt_access_token',
            access_token,
            max_age=max_age_access,
            httponly=True,
            secure=True,
            samesite=settings.DJWTO_SAME_SITE,
            domain=settings.DJWTO_DOMAIN
        )
        return response
    raise ImproperlyConfigured(
        'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
        f'Received "{mode}" instead.'
    )


class RefreshAccessView(View):
    """
    Uses the refresh token to create a new access one.
    """
    @method_decorator(csrf_exempt)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    @_build_decorator(csrf_protect)
    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_is_refresh)
    def post(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        refresh_claims = request.payload

        if settings.DJWTO_JTI_CLAIM:
            jti = refresh_claims['jti']
            if models.JWTBlacklist.is_blacklisted(jti):
                return JsonResponse({'error': "Can't update access token."},
                                    status=500)

        access_claims = tokens.get_access_claims_from_refresh(refresh_claims)
        msg = 'Access token successfully refreshed.'
        response = build_tokens_response(refresh_claims, access_claims, msg)

        signals.jwt_access_refreshed.send(
            sender=type(self).__name__,
            request=request,
            refresh_claims=refresh_claims,
            access_claims=access_claims
        )

        return response


class UpdateRefreshView(View):
    """
    Updates the expiration time of the refresh token. This is particularly useful in
    scenarios such as web eCommerces where the customer might be close to finalize its
    purchase and the token goes expired during the checkout.

    In this view the client has the opportunity of updating the refresh token thus
    avoiding a login requirement on inconvenient moments.

    The `settings.DJWTO_ALLOW_REFRESH_UPDATE` must be `True`, the token must not be
    blacklisted already (valid only if "JTI" is available) and the user must have a
    `is_active` flag equal to `True` from the db (if "user" is available in JWT token).
    """
    @method_decorator(csrf_exempt)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    @_build_decorator(csrf_protect)
    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_is_refresh)
    def post(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        fail_resp = JsonResponse({'error': "Can't update refresh token."}, status=500)
        refresh_claims = request.payload

        if not settings.DJWTO_ALLOW_REFRESH_UPDATE:
            return fail_resp

        if settings.DJWTO_JTI_CLAIM:
            jti = refresh_claims['jti']
            if models.JWTBlacklist.is_blacklisted(jti):
                return fail_resp

        user_data = refresh_claims.get('user')
        if user_data:
            User = get_user_model()
            try:
                username = user_data.get(User.USERNAME_FIELD)
                # TODO: typing is not recognizing `get_by_natural_key` here
                user = User.objects.get_by_natural_key(username)  # type: ignore
            except User.DoesNotExist:
                return fail_resp
            if not user.is_active:
                return JsonResponse({'error': 'User is inactive.'}, status=403)

        iat = datetime.utcnow()
        refresh_claims['exp'] = timegm(
            (iat + settings.DJWTO_REFRESH_TOKEN_LIFETIME).utctimetuple()
        )
        if 'iat' in refresh_claims:
            refresh_claims['iat'] = timegm(iat.utctimetuple())
        access_claims = tokens.get_access_claims_from_refresh(refresh_claims)
        msg = 'Refresh token successfully updated.'
        response = build_tokens_response(refresh_claims, access_claims, msg)

        signals.jwt_refresh_updated.send(
            sender=type(self).__name__,
            request=request,
            refresh_claims=refresh_claims,
            access_claims=access_claims
        )

        return response


class GetTokensView(View):
    """
    Creates the JWT Token and stores then according to the specification in
    `settings.DJWTO_MODE`.
    """
    @method_decorator(csrf_exempt)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    @_build_decorator(ensure_csrf_cookie)
    def post(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        try:
            _ = auth.get_raw_token_from_request(request)
            return JsonResponse({'msg': 'User already authenticated.'}, status=200)
        except (JWTValidationError, ImproperlyConfigured):
            pass

        try:
            user = auth.user_authenticate(request)
        except ValidationError as err:

            signals.jwt_login_fail.send(
                sender=type(self).__name__,
                request=request,
                error=err.args[0]
            )

            return JsonResponse({'error': err.args[0]}, status=401,
                                headers=HEADERS401)

        try:
            refresh_claims = tokens.process_claims(user, request, 'refresh', args,
                                                   kwargs)
            access_claims = tokens.get_access_claims_from_refresh(refresh_claims)
            msg = 'Tokens successfully created.'
            response = build_tokens_response(refresh_claims,  access_claims, msg)

            signals.jwt_logged_in.send(
                sender=type(self).__name__,
                request=request,
                refresh_claims=refresh_claims,
                access_claims=access_claims
            )

            rotate_token(request)

            return response

        except ImproperlyConfigured as err:

            signals.jwt_login_fail.send(
                sender=type(self).__name__,
                request=request,
                error=err.args[0]
            )
            # As it's an internal error then don't return full error message to the
            # client. It should be handled internally by the server side.
            return JsonResponse({'error': 'Failed to process request.'}, status=500)


class ValidateTokensView(View):
    """
    Extracts the jwt token from income `request` and assess if the token is valid.
    """
    @method_decorator(csrf_exempt)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    @_build_decorator(csrf_protect)
    @method_decorator(auth.jwt_login_required)
    def post(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        """
        In some scenarios it's interesting to have an endpoint which a client can ask
        whether a given token is valid or not. Notice that even if the token has been
        Blacklisted but it's still valid the response will confirm its validity.

        It's been designed like that because blacklisted tokens are still valid for its
        expiration time. Only when requesting for updating the refresh token is that the
        blacklist API is checked.
        """
        signals.jwt_token_validated.send(sender=type(self).__name__, request=request)
        return JsonResponse({'msg': 'Token is valid'})


class BlackListTokenView(View):
    """
    Extracts the jwt token from income `request` and adds it to the Blacklist table.
    The Blacklist functionality is only available if `settings.DJWTO_JTI_CLAIM` is `True`

    Only the refresh token can be blacklisted. After the operation, available cookies are
    deleted accordingly as well.
    """
    @method_decorator(csrf_exempt)
    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        return super().dispatch(request, *args, **kwargs)

    @_build_decorator(csrf_protect)
    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_is_refresh)
    def post(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        jti = request.payload.get('jti')
        if not jti:
            error_msg = (
                'No jti claim was available in the input token. The value is mandatory'
                ' in order to use the Blacklist API.'
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

        exp = request.payload.get('exp')
        if exp:
            exp = datetime.utcfromtimestamp(exp)

        models.JWTBlacklist.objects.get_or_create(
            jti=jti,
            token=request.token,
            expires=exp
        )

        signals.jwt_blacklisted.send(
            sender=type(self).__name__,
            request=request,
            jti=jti
        )

        return JsonResponse({'msg': 'Token successfully blacklisted.'}, status=200)

    @_build_decorator(csrf_protect)
    @method_decorator(auth.jwt_login_required)
    def delete(
        self,
        request: auth.THttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        """
        Deletes both tokens cookies.
        """
        if settings.DJWTO_MODE == 'JSON':
            return JsonResponse({'msg': 'No token to delete.'}, status=204)

        response = JsonResponse({'msg': 'Tokens successfully deleted.'})
        response.delete_cookie(
            'jwt_refresh',
            path=f'/{settings.DJWTO_REFRESH_COOKIE_PATH}',
            domain=settings.DJWTO_DOMAIN,
            samesite=settings.DJWTO_SAME_SITE
        )

        if settings.DJWTO_MODE == 'ONE-COOKIE':
            response.delete_cookie(
                'jwt_access',
                domain=settings.DJWTO_DOMAIN,
                samesite=settings.DJWTO_SAME_SITE
            )

        if settings.DJWTO_MODE == 'TWO-COOKIES':
            response.delete_cookie(
                'jwt_access_payload',
                domain=settings.DJWTO_DOMAIN,
                samesite=settings.DJWTO_SAME_SITE
            )
            response.delete_cookie(
                'jwt_access_token',
                domain=settings.DJWTO_DOMAIN,
                samesite=settings.DJWTO_SAME_SITE
            )
        return response
