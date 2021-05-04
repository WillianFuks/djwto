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
from typing import Any, Dict

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.http.request import HttpRequest
from django.http.response import JsonResponse
from django.views import View

import djwto.authenticate as auth
import djwto.tokens as tokens


HEADERS401 = {'WWW-Authenticate': auth.WWWAUTHENTICATE}


class GetTokensView(View):
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

            return self._build_response(refresh_token,  access_token, refresh_claims,
                                        access_claims, )

        except ImproperlyConfigured:
            # As it's an internal error then don't return full error message to the
            # client. It should be handled internally by the server side.
            return JsonResponse({'error': 'Failed to process request.'}, status=500)

    def _build_response(
            self,
            refresh_token: str,
            access_token: str,
            refresh_claims: Dict[str, Any],
            access_claims: Dict[str, Any],
    ) -> JsonResponse:
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
          refresh_claims: Dict[str, Any]
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

        access_exp = access_claims.get('exp')
        refresh_exp = refresh_claims.get('exp')

        response = JsonResponse({})
        response.set_cookie(
            'jwt_refresh',
            refresh_token,
            max_age=refresh_exp,
            httponly=True,
            secure=True,
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE
        )
        if mode == 'ONE-COOKIE':
            response.set_cookie(
                'jwt_access',
                access_token,
                max_age=access_exp,
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            return response
        if mode == 'TWO-COOKIES':
            jwt, _, signature = access_token.rpartition('.')
            value = {'jwt': jwt, 'payload': access_claims}
            response.set_cookie(
                'jwt_access_payload',
                json.dumps(value, sort_keys=True, cls=DjangoJSONEncoder),
                max_age=access_exp,
                httponly=False,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            response.set_cookie(
                'jwt_access_signature',
                signature,
                max_age=access_exp,
                httponly=True,
                secure=True,
                samesite=settings.DJWTO_SAME_SITE
            )
            return response
        raise ImproperlyConfigured(
            'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
            f'Received "{mode}" instead.'
        )
