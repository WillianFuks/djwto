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
import mock
import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured

import djwto.tokens as tokens
from djwto.exceptions import JWTValidationError


class TestProcessClaims:
    def test_process_claims_raises(self, settings, rf):
        alice = None
        settings.DJWTO_ISS_CLAIM = 1
        request = rf.post('')
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Issuer must be str. Received int instead.'
        )
        settings.DJWTO_ISS_CLAIM = None

        settings.DJWTO_SUB_CLAIM = 1
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Subject must be str. Received int instead.'
        )
        settings.DJWTO_SUB_CLAIM = None

        settings.DJWTO_AUD_CLAIM = 1
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Audience must be either List[str] or str. Received int instead.'
        )

        settings.DJWTO_AUD_CLAIM = ['1', 1]
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Audience must be either List[str] or str. '
            'Received List[list] instead.'
        )
        settings.DJWTO_AUD_CLAIM = None

        settings.DJWTO_REFRESH_TOKEN_LIFETIME = 1
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Refresh token lifetime must be a `timedelta` object.'
        )
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(minutes=-1)
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Refresh token expiration time must be positive.'
        )

    @pytest.mark.django_db
    def test_process_claims(self, settings, rf, monkeypatch, date_mock):
        d_mock = mock.Mock()
        uuid_mock = mock.Mock()

        d_mock.utcnow.return_value = date_mock
        uuid_mock.uuid4.return_value = 'uuid'

        settings.DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(seconds=1)
        settings.DJWTO_NBF_LIFETIME = timedelta(seconds=1)
        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'

        monkeypatch.setattr('djwto.tokens.datetime', d_mock)
        monkeypatch.setattr('djwto.tokens.uuid', uuid_mock)
        alice = User.objects.get(username='alice')
        request = rf.post('')
        result = tokens.process_claims(alice, request)
        assert result == {
            'iss': 'iss',
            'sub': 'sub',
            'aud': 'aud',
            'iat': date_mock,
            'exp': date_mock + settings.DJWTO_REFRESH_TOKEN_LIFETIME,
            'nbf': date_mock + settings.DJWTO_NBF_LIFETIME,
            'jti': 'uuid',
            'type': 'refresh',
            'user': {
                'username': 'alice',
                'id': 1
            }
        }

        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_AUD_CLAIM = ['1', '2']
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = None
        settings.DJWTO_NBF_LIFETIME = None
        settings.DJWTO_JTI_CLAIM = None
        result = tokens.process_claims(None, request)
        assert result == {'iss': 'iss', 'sub': 'sub', 'aud': ['1', '2'],
                          'type': 'refresh'}


class TestGetAccessClaimsFromRefresh:
    def test_get_access_from_refresh_raises(self, settings):
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(seconds=-1)
        settings.DJWTO_IAT_CLAIM = False
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.get_access_claims_from_refresh({})
        assert exec_info.value.args[0] == (
            'Refresh token expiration time must be positive.'
        )

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = 1
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = tokens.get_access_claims_from_refresh({})
        assert exec_info.value.args[0] == (
            'Refresh token lifetime must be a `timedelta` object.'
        )

    def test_get_access_from_refresh(self, settings, monkeypatch, date_mock):
        claims = {'sub': 'sub'}
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = None
        settings.DJWTO_IAT_CLAIM = False
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub', 'type': 'access'}

        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)
        settings.DJWTO_IAT_CLAIM = True
        claims['iat'] = date_mock
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub', 'iat': date_mock,
                                 'refresh_iat': 1609462860.0,
                                 'type': 'access'}

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        access_claims = tokens.get_access_claims_from_refresh(claims)
        expected_exp = date_mock + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        assert access_claims == {'sub': 'sub', 'iat': date_mock, 'exp': expected_exp,
                                 'refresh_iat': 1609462860.0,
                                 'type': 'access'}


class TestEncodeClaims:
    def test_encode_claims(self, settings):
        claims = {'sub': 'sub'}
        expected = pyjwt.encode(claims, 'test key')
        jwt = tokens.encode_claims(claims)
        assert jwt == expected


class TestDecodeToken:
    def test_decode_token_raises(self, settings):
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
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Signature has expired'

        token = 'abc.def.ghi'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == (
            "Invalid header string: 'utf-8' codec can't "
            "decode byte 0xb7 in position 1: invalid start byte"
        )

        payload = {'nbf': datetime.now() + timedelta(days=1)}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'The token is not yet valid (nbf)'

        settings.DJWTO_ISS_CLAIM = 'iss'
        payload = {}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "iss" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        payload = {'iss': 'iss'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "sub" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        payload = {'iss': 'iss', 'sub': 'sub'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "aud" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        payload = {'iss': 'iss', 'sub': 'sub', 'aud': 'aud'}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "iat" claim'

        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'
        settings.DJWTO_IAT_CLAIM = True
        settings.DJWTO_JTI_CLAIM = True
        payload = {'iss': 'iss', 'sub': 'sub', 'aud': 'aud', 'iat': datetime.now()}
        token = pyjwt.encode(payload, sign_key, algorithm='HS256')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = tokens.decode_token(token)
        assert exec_info.value.args[0] == 'Token is missing the "jti" claim'

    def test_decode_token(self, settings):
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
        result = tokens.decode_token(token)
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
        result = tokens.decode_token(token)
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
        result = tokens.decode_token(token)
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
        result = tokens.decode_token(token)
        assert result == payload
