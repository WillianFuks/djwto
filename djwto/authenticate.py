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


from typing import Any, Callable, Dict, Optional, Tuple, TypeVar
from typing_extensions import Literal

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import AbstractBaseUser
from django.http.request import HttpRequest

U = TypeVar('U', bound=AbstractBaseUser)
ErrorsType = Dict[Literal['errors'], Dict[Any, Any]]
ReturnAuthCallType = Tuple[Optional[U], ErrorsType]
AuthCallType = Callable[[HttpRequest], ReturnAuthCallType]


def default_user_authenticate(request: HttpRequest) -> ReturnAuthCallType:
    """
    Default method used for authenticating users; tools already available in Django are
    used here.

    Args
    ----
      request: HttpRequest
          Request object as received by the web server processor (either WSGI or ASGI),
          expected to contain the field `data` filled with user name and password.

    Returns
    -------
      (user, errors): ReturnAuthCallType
          If user successfully authenticate then returns their correspondent object from
          Django's default `User` model; returns `None` otherwise.
          Second element in tuple is a dict whose only key 'errors' is empty if input
          data is valid and a dict with errors otherwise.
    """
    errors: ErrorsType = {'errors': {}}
    form = AuthenticationForm(data=request.POST)
    form.is_valid()
    errors['errors'] = dict(form.errors)
    return form.get_user(), errors
