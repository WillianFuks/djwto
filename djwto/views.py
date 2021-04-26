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

from typing import Any

from django.conf import settings
from django.http.request import HttpRequest
from django.http.response import JsonResponse
from django.utils.module_loading import import_string
from django.views import View

from djwto.authenticate import AuthCallType
import djwto.tokens
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
