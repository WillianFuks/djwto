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
from typing import Any, Dict, Optional, cast
from django.core.serializers.json import DjangoJSONEncoder

from django.conf import settings
from django.http.request import HttpRequest
from django.http.response import JsonResponse
from django.utils.module_loading import import_string
from django.views import View

import djwto.tokens as tokens
from djwto.authenticate import AuthCallType
from djwto.tokens import ClaimProcessCallType


user_authenticate: AuthCallType = import_string(settings.DJWTO_USER_AUTHENTICATE)
process_claims: ClaimProcessCallType = import_string(settings.DJWTO_CLAIMS_PROCESS)


class GetTokensView(View):
    def __init__(
        self,
        user_authenticate: AuthCallType = user_authenticate,
        process_claims: ClaimProcessCallType = process_claims,
    ):
        self.user_authenticate = user_authenticate
        self.process_claims = process_claims

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        user, errors = self.user_authenticate(request)

        if errors['errors']:
            return JsonResponse(errors)

        refresh_claims = self.process_claims(user, request, args, kwargs)
        access_claims = tokens.get_access_claims_from_refresh(refresh_claims)

        refresh_token = tokens.encode_claims(refresh_claims)
        access_token = tokens.encode_claims(access_claims)

        return self._build_response(refresh_token,  access_token, access_claims)

    def _build_response(self, refresh_token: str, access_token: str,
                        payload: Optional[Dict[str, Any]] = None) -> JsonResponse:
        """
        djwto offers 3 main modes for returning a response: "JSON", "ONE-COOKIE" or
        "TWO-COOKIES". This method builds the http response in accordance to what
        `settings.DJWTO_MODE` specifies.

        For "JSON" option, the tokens as simply put into
        a dictionary and returned as a JSON response type. For "ONE-COOKIE", each token
        (refresh and access) is saved into a separate respective cookie and finally for
        "TWO-COOKIES" the access token is divided in two partes: payload and signature.

        The payload part is publicly available for reading by the client whereas the
        signature is saved as HttpOnly. This allows for the front-end to interact with
        the JWT content without running the risk of compromising the signature.

        Args
        ----
          refresh_token: str
              Token already encoded.
          access_token: str
          payload: Optional[Dict[str, Any]]
              If `settings.DJWTO_MODE == 'TWO-COOKIES'` then it's expected the value of
              `payload` will contain the values of the access claims in Dict format to be
              serialized in the cookie content. This allows the front-end to have access
              to the values. The signature of the cookie is still separated and stored
              under `HttpOnly` and `Secure` conditions.

        Returns
        -------
          JsonResponse
              Returns tokens in accordance to `settings.DJWTO_MODE` value.
        """
        mode = settings.DJWTO_MODE
        if mode == 'JSON':
            return JsonResponse({'refresh': refresh_token, 'access': access_token})

        response = JsonResponse({})
        response.set_cookie(
            'jwt_refresh',
            refresh_token,
            max_age=cast(int, settings.DJWTO_REFRESH_TOKEN_LIFETIME.total_seconds()),
            httponly=True,
            secure=True,
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE
        )
        if mode == 'ONE-COOKIE':
            response.set_cookie(
                'jwt_access',
                access_token,
                max_age=cast(int, settings.DJWTO_ACCESS_TOKEN_LIFETIME.total_seconds()),
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            return response
        if mode == 'TWO-COOKIES':
            response.set_cookie(
                'jwt_access_payload',
                json.dumps(payload, sort_keys=True, cls=DjangoJSONEncoder),
                max_age=cast(int, settings.DJWTO_ACCESS_TOKEN_LIFETIME.total_seconds()),
                httponly=False,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            response.set_cookie(
                'jwt_access_signature',
                access_token.rpartition('.')[-1],
                max_age=cast(int, settings.DJWTO_ACCESS_TOKEN_LIFETIME.total_seconds()),
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )

            return response

        raise ValueError(
            'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
            f'Received "{mode}" instead.'
        )
