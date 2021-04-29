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


from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional

import uuid
import jwt
from django.conf import settings
from django.http import HttpRequest
from djwto.authenticate import U


ClaimProcessCallType = Callable[[U, HttpRequest, Any, Any], Dict[Any, Any]]


def default_process_claims(
    user: Optional[U],
    request: HttpRequest,
    *args: Any,
    **kwargs: Any
) -> Dict[Any, Any]:
    """
    Default processing of claims that are usually available on JWTs such as `sub`, `iss`,
    `aud` and so on. It's intention is to work as a general solution for most use cases
    of JWT creation.

    Separating this step in a contained function allows for customizing the values used
    on each JWT claim, such as, for instance, extracting a specific value of 'audience'
    for each user based on Cookies or Meta data available in input `request`.

    The default version simply uses values available on the file `settings.py`.

    Args
    ----
      user: Optional[U]
          Object as retrieved from the database representing the user. It's optional so
          extensions of this function doesn't have to input a user object case it's not
          required.
      request: HttpRequest
          Input request received from the WSGI (or ASGI) server.
      args, kwargs: Any
          Those remain as a signature reference for the scenario where one wants to
          extend the functionality of this function.

    Returns
    ------
      claims: Dict[Any, Any]
          Default values of claim fields as specified in the `settings.py` file.
    """
    claims: Dict[Any, Any] = {}
    iss = settings.DJWTO_ISS_CLAIM
    if iss:
        if not isinstance(iss, str):
            raise ValueError(
                f'Value of Issuer must be str. Received {type(iss).__name__} instead.'
            )
        claims['iss'] = iss

    sub = settings.DJWTO_SUB_CLAIM
    if sub:
        if not isinstance(sub, str):
            raise ValueError(
                f'Value of Subject must be str. Received {type(sub).__name__} instead.'
            )
        claims['sub'] = sub

    aud = settings.DJWTO_AUD_CLAIM
    if aud:
        if not isinstance(aud, list):
            if not isinstance(aud, str):
                raise ValueError(
                    'Value of Audience must be either List[str] or str. '
                    f'Received {type(aud).__name__} instead.'
                )
        else:
            for e in aud:
                if not isinstance(e, str):
                    raise ValueError(
                        'Value of Audience must be either List[str] or str. '
                        f'Received List[{type(aud).__name__}] instead.'
                    )
        claims['aud'] = aud

    # First it builds claims for refresh token and then access token is copied from it.
    exp_timedelta = settings.DJWTO_REFRESH_TOKEN_LIFETIME

    iat = datetime.utcnow()
    if settings.DJWTO_IAT_CLAIM:
        claims['iat'] = iat

    if exp_timedelta:
        _validate_timedelta_claim(exp_timedelta)
        exp = iat + exp_timedelta
        claims['exp'] = exp

    nbf_timedelta = settings.DJWTO_NBF_LIFETIME
    if nbf_timedelta:
        _validate_timedelta_claim(exp_timedelta)
        nbf = iat + nbf_timedelta
        claims['nbf'] = nbf

    if settings.DJWTO_JTI_CLAIM:
        jti = str(uuid.uuid4())
        claims['jti'] = jti

    if user:
        claims['username'] = user.get_username()
        claims['user_id'] = user.pk
    return claims


def _validate_timedelta_claim(claim: Optional[timedelta]) -> None:
    """
    Receives as input the setting value for a given claim that may contain timedelta
    type, checking if it's valid.

    Args
    ----
      claim: Optional[timedelta]
          Value from input setting.

    Raises
    ------
      ValueError: If claim is not of type `timedelta`.
                  If timdelta is negative.
    """
    if not isinstance(claim, timedelta):
        raise ValueError(
            'Refresh token lifetime must be a `timedelta` object.'
        )
    if claim.total_seconds() < 0:
        raise ValueError(
            'Refresh token expiration time must be positive.'
        )


def get_access_claims_from_refresh(refresh_claims: Dict[Any, Any]) -> Dict[Any, Any]:
    """
    Uses the claims built for the refresh token to create the access one. Main difference
    is that the latter might have a lower expiration date (still, this field is optional,
    if `settings.DJWTO_ACCESS_TOKEN_LIFETIME` is `None` then access token won't have it.

    Args
    ----
      refresh_claims: Dict[Any, Any]
          Dict object where keys are the claims names of the refresh token as extracted
          from user and `request` input.

    Returns
    -------
      access_claims: Dict[Any, Any]
          It's basically a copy of the refresh token with a few changes, if applicable.

    Raises
    ------
      ValueError: If claim is not of type `timedelta`.
                  If timdelta is negative.
    """
    # Uses a shallow copy for now. Maybe in the future it might require a deep copy.
    # This forces the tokens to have the claims at the first level of the dict.
    access_claims = refresh_claims.copy()
    iat = datetime.utcnow()
    if settings.DJWTO_IAT_CLAIM:
        access_claims['iat'] = iat
    access_timedelta = settings.DJWTO_ACCESS_TOKEN_LIFETIME
    if access_timedelta:
        _validate_timedelta_claim(access_timedelta)
        access_claims['exp'] = iat + access_timedelta
    return access_claims


def encode_claims(claims: Dict[Any, Any]) -> str:
    """
    Uses the dict of claims built from the request and transforms to JWT using the chosen
    algorithm and key from the `settings.py` file.

    Args
    ----
      claims: Dict[Any, Any]
          Input claims to be encoded in JWT.

    Returns
    -------
      str
          Final encoded JWT form.
    """
    return jwt.encode(claims, settings.DJWTO_SIGNING_KEY,
                      algorithm=settings.DJWTO_ALGORITHM)
