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


import uuid
from calendar import timegm
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import jwt as pyjwt
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

import djwto.exceptions as exceptions
import djwto.settings as settings


def process_claims(
    user: Optional[User],
    request: HttpRequest,
    type_: str = 'refresh',
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
      user: Optional[User]
          Object as retrieved from the database representing the user. It's optional so
          extensions of this function doesn't have to input a user object case it's not
          required.
      request: HttpRequest
          Input request received from the WSGI (or ASGI) server.
      type_: str
          Whether these claims refers to a refresh or access token.
      args, kwargs: Any
          Those remain as a signature reference for the scenario where one wants to
          extend the functionality of this function.

    Returns
    ------
      claims: Dict[Any, Any]
          Default values of claim fields as specified in the `settings.py` file.

    Raises
    ------
      ImproperlyConfigured: If values in file `settings.py` are invalid.
    """
    claims: Dict[Any, Any] = {}
    iss = settings.DJWTO_ISS_CLAIM
    if iss:
        if not isinstance(iss, str):
            raise ImproperlyConfigured(
                f'Value of Issuer must be str. Received {type(iss).__name__} instead.'
            )
        claims['iss'] = iss

    sub = settings.DJWTO_SUB_CLAIM
    if sub:
        if not isinstance(sub, str):
            raise ImproperlyConfigured(
                f'Value of Subject must be str. Received {type(sub).__name__} instead.'
            )
        claims['sub'] = sub

    aud = settings.DJWTO_AUD_CLAIM
    if aud:
        if not isinstance(aud, list):
            if not isinstance(aud, str):
                raise ImproperlyConfigured(
                    'Value of Audience must be either List[str] or str. '
                    f'Received {type(aud).__name__} instead.'
                )
        else:
            for e in aud:
                if not isinstance(e, str):
                    raise ImproperlyConfigured(
                        'Value of Audience must be either List[str] or str. '
                        f'Received List[{type(aud).__name__}] instead.'
                    )
        claims['aud'] = aud

    # First it builds claims for refresh token and then access token is copied from it.
    exp_timedelta = settings.DJWTO_REFRESH_TOKEN_LIFETIME

    iat = datetime.utcnow()
    if settings.DJWTO_IAT_CLAIM:
        claims['iat'] = timegm(iat.utctimetuple())

    if exp_timedelta:
        _validate_timedelta_claim(exp_timedelta)
        exp = iat + exp_timedelta
        claims['exp'] = timegm(exp.utctimetuple())

    nbf_timedelta = settings.DJWTO_NBF_LIFETIME
    if nbf_timedelta:
        _validate_timedelta_claim(exp_timedelta)
        nbf = iat + nbf_timedelta
        claims['nbf'] = timegm(nbf.utctimetuple())

    if settings.DJWTO_JTI_CLAIM:
        jti = str(uuid.uuid4())
        claims['jti'] = jti

    # This is necessary for the case when mode is 'JSON' as it's the only way to
    # identify which token is which
    claims['type'] = 'refresh'

    if user:
        claims['user'] = process_user(user)
    return claims


def process_user(user: User) -> Dict[str, Union[str, int, List[str]]]:
    """
    Process various data related to the database User object. This function can be
    replaced in order to build a different claim set for the user.

    Args
    ----
      user: User
          Object user as retrieved from the database.

    Returns
    -------
      Dict[str, str]
          User claims to store in the token payload.
    """
    return {
        user.USERNAME_FIELD: user.get_username(),
        'id': user.pk,
        'perms': process_perms(user)
    }


def process_perms(user: User) -> List[str]:
    """
    Gets permissions from input user and returns a list with those values. Default
    function gets all permissions (by running `user.get_all_permissions()`). Change this
    funtion, by running:

    >>> import djwto.authentication as auth
    >>> auth.process_perms = new_perms_func

    Args
    ----
      user: User
          Input user as retrieved from database.

    Returns
    ------
      perms: List[str]
          List of permissions extracted from user. By default returns all perms.
    """
    return list(user.get_all_permissions())


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
      ImproperlyConfigured: If claim is not of type `timedelta`.
                  If timdelta is negative.
    """
    if not isinstance(claim, timedelta):
        raise ImproperlyConfigured(
            'Refresh token lifetime must be a `timedelta` object.'
        )
    if claim.total_seconds() < 0:
        raise ImproperlyConfigured(
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
      ImproperlyConfigured: If claim is not of type `timedelta`.
                  If timdelta is negative.
    """
    # Uses a shallow copy for now. Maybe in the future it might require a deep copy.
    # This forces the tokens to have the claims at the first level of the dict.
    access_claims = refresh_claims.copy()
    iat = datetime.utcnow()
    if settings.DJWTO_IAT_CLAIM:
        # Keep the value of the emission of the refresh token which allows for the front-
        # end to read its value on `DJWTO_MODE == 'TWO-COOKIES'` option and evaluate
        # whether it's necessary to create a new refresh token. This is useful for
        # instance on eCommerce websites that might not want to logout a customer that is
        # still currently active on the website.
        refresh_iat = access_claims['iat']
        access_claims['iat'] = timegm(iat.utctimetuple())
        access_claims['refresh_iat'] = refresh_iat
    access_timedelta = settings.DJWTO_ACCESS_TOKEN_LIFETIME
    access_claims['type'] = 'access'
    if access_timedelta:
        _validate_timedelta_claim(access_timedelta)
        access_claims['exp'] = timegm((iat + access_timedelta).utctimetuple())
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
    return pyjwt.encode(claims, settings.DJWTO_SIGNING_KEY,
                        algorithm=settings.DJWTO_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
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


    Args
    ----
      token: str
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
    require: List[str] = []

    def _update(name: str, value: Any) -> None:
        if value:
            kwargs[name] = value
            require.append(name[:3])

    _update('issuer', iss)
    _update('subject', sub)
    _update('audience', aud)
    _update('iat', iat_flag)
    _update('jti', jti_flag)

    kwargs['options'] = {'require': require}

    try:
        payload = pyjwt.decode(token, ver_key if ver_key else sign_key, alg, **kwargs)
        return payload
    except (
        pyjwt.ExpiredSignatureError,
        pyjwt.ImmatureSignatureError,
        pyjwt.MissingRequiredClaimError,
        pyjwt.DecodeError,
        pyjwt.InvalidTokenError
    ) as err:
        raise exceptions.JWTValidationError(str(err))
