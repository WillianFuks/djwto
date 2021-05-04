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


from calendar import timegm
from datetime import datetime, timedelta

import jwt as pyjwt
import pytest
from django.core.exceptions import ImproperlyConfigured, ValidationError

from djwto.authenticate import JWTAuthentication, user_authenticate
from djwto.exceptions import JWTValidationError


@pytest.mark.django_db
class TestAuthenticator:
    def test_user_authenticate(self, rf):
        request = rf.post('', {'username': 'alice', 'password': 'pass'})
        user = user_authenticate(request)
        assert user.username == 'alice'

    def test_user_authenticator_invalid_data_raises(self, rf):
        request = rf.post('', {'username': '', 'password': 'pass'})
        with pytest.raises(ValidationError) as exec_info:
            _ = user_authenticate(request)
        assert exec_info.value.args[0] == (
            '{"username": ["This field is required."]}'
        )

        request = rf.post('', {'username': 'alice', 'password': 'wrong pass'})
        with pytest.raises(ValidationError) as exec_info:
            _ = user_authenticate(request)
        assert exec_info.value.args[0] == (
            '{"__all__": ["Please enter a correct username and password. Note that both '
            'fields may be case-sensitive."]}'
        )


class TestJWTAuthentication:
    def test_get_raw_token_from_request_raises(self, rf, settings):
        request = rf.post('')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Token not found in "HTTP_AUTHORIZATION" header.'
        )

        request.META['HTTP_AUTHORIZATION'] = 'Authorization: Bearer '
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Value in HTTP_AUTHORIZATION header is not valid.'
        )

        settings.DJWTO_MODE = 'ONE-COOKIE'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Cookie "jwt_access" value is empty.'
        )

        request.COOKIES['jwt_access'] = ''
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Cookie "jwt_access" value is empty.'
        )

        settings.DJWTO_MODE = 'TWO-COOKIES'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Signature cookie value cannot be empty.'
        )

        request.COOKIES['jwt_access_signature'] = 'ghi'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Access payload cannot be empty.'
        )

        request.COOKIES['jwt_access_payload'] = ''
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Access payload cannot be empty.'
        )

        request.COOKIES['jwt_access_payload'] = '{}'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Invalid value of access payload token.'
        )

        request.COOKIES['jwt_access_payload'] = '{"abc}'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Invalid value of access payload token.'
        )

        settings.DJWTO_MODE = 'invalid setting'
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = JWTAuthentication.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Value of `settings.DJWTO_MODE` is invalid. Expected either "JSON", '
            '"ONE-COOKIE" or "TWO-COOKIES". Received "invalid setting" instead.'
        )

    def test_get_raw_token_from_request(self, rf, settings):
        request = rf.post('')
        expected = 'abc.def.ghi'
        request.META['HTTP_AUTHORIZATION'] = 'Authorization: Bearer abc.def.ghi'
        token = JWTAuthentication.get_raw_token_from_request(request)
        assert token == expected

        settings.DJWTO_MODE = 'ONE-COOKIE'
        request.COOKIES['jwt_access'] = expected
        token = JWTAuthentication.get_raw_token_from_request(request)
        assert token == expected

        settings.DJWTO_MODE = 'TWO-COOKIES'
        request.COOKIES['jwt_access_payload'] = (
            f'{{"jwt": "{expected.rpartition(".")[0]}"}}'
        )
        request.COOKIES['jwt_access_signature'] = expected.rpartition('.')[-1]
        token = JWTAuthentication.get_raw_token_from_request(request)
        assert token == expected

    def test_validate_token_raises(self, settings):
        sign_key = 'sign key'
        settings.DJWTO_SIGNING_KEY = sign_key
        settings.DJWTO_VERIFYING_KEY = None
        settings.DJWTO_ALGORITHM = 'HS256'
        settings.DJWTO_ISS_CLAIM = None
        settings.DJWTO_SUB_CLAIM = None
        settings.DJWTO_AUD_CLAIM = None
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False

        payload = {'exp': datetime(2021, 1, 1)}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Signature has expired'

        token = 'abc.def.ghi'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == (
            "Invalid header string: 'utf-8' codec can't "
            "decode byte 0xb7 in position 1: invalid start byte"
        )

        payload = {'nbf': datetime.now() + timedelta(days=1)}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'The token is not yet valid (nbf)'

        settings.DJWTO_ISS_CLAIM = 'iss'
        payload = {}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "iss" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        payload = {'iss': 'iss'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "sub" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        payload = {'iss': 'iss', 'sub': 'sub'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "aud" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        payload = {'iss': 'iss', 'sub': 'sub', 'aud': 'aud'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "iat" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        settings.DJWTO_JTI_CLAIM = True
        payload = {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': datetime.now()}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = JWTAuthentication.validate_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "jti" claim'

    def test_validate_token(self, settings):
        sign_key = 'sign key'
        settings.DJWTO_SIGNING_KEY = sign_key
        settings.DJWTO_VERIFYING_KEY = None
        settings.DJWTO_ALGORITHM = 'HS256'
        settings.DJWTO_ISS_CLAIM = None
        settings.DJWTO_SUB_CLAIM = None
        settings.DJWTO_AUD_CLAIM = None
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False

        exp = datetime.now() + timedelta(days=1)
        payload = {'exp': timegm(exp.utctimetuple())}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        result = JWTAuthentication.validate_token(token)
        assert result == payload

        sign_key = 'sign key'
        settings.DJWTO_SIGNING_KEY = sign_key
        settings.DJWTO_VERIFYING_KEY = None
        settings.DJWTO_ALGORITHM = 'HS256'
        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        settings.DJWTO_JTI_CLAIM = True

        exp = datetime.now() + timedelta(days=1)
        payload = {'exp': timegm(exp.utctimetuple()), 'iss': 'iss', 'sub': 'sub',
                   'aud': 'aud', 'iat': True, 'jti': True}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        result = JWTAuthentication.validate_token(token)
        assert result == payload

        sign_key = 'sign key'
        settings.DJWTO_SIGNING_KEY = sign_key
        settings.DJWTO_VERIFYING_KEY = None
        settings.DJWTO_ALGORITHM = 'HS256'
        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = ['aud0', 'aud1']
        settings.DJWTO_IAT_CLAIM = True
        settings.DJWTO_JTI_CLAIM = True

        exp = datetime.now() + timedelta(days=1)
        payload = {'exp': timegm(exp.utctimetuple()), 'iss': 'iss', 'sub': 'sub',
                   'aud': ['aud0', 'aud1'], 'iat': True, 'jti': True}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        result = JWTAuthentication.validate_token(token)
        assert result == payload

        sign_key = open('tests/fixtures/keys/jwtRS256.key', 'rb').read()
        settings.DJWTO_SIGNING_KEY = sign_key
        settings.DJWTO_VERIFYING_KEY = (
            open('tests/fixtures/keys/jwtRS256.key.pub', 'rb').read()
        )
        settings.DJWTO_ALGORITHM = 'RS256'
        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        settings.DJWTO_JTI_CLAIM = True

        exp = datetime.now() + timedelta(days=1)
        payload = {'exp': timegm(exp.utctimetuple()), 'iss': 'iss', 'sub': 'sub',
                   'aud': 'aud', 'iat': True, 'jti': True}
        token = pyjwt.encode(payload, sign_key, algorithm='RS256')
        result = JWTAuthentication.validate_token(token)
        assert result == payload
