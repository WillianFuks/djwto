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

import pytest
import mock
import jwt as pyjwt
from datetime import timedelta
import djwto.tokens as tokens

from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured


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
            'username': 'alice',
            'user_id': 1
        }

        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_AUD_CLAIM = ['1', '2']
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = None
        settings.DJWTO_NBF_LIFETIME = None
        settings.DJWTO_JTI_CLAIM = None
        result = tokens.process_claims(None, request)
        assert result == {'iss': 'iss', 'sub': 'sub', 'aud': ['1', '2']}


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
        assert access_claims == {'sub': 'sub'}

        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)
        settings.DJWTO_IAT_CLAIM = True
        claims['iat'] = date_mock
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub', 'iat': date_mock,
                                 'refresh_iat': 1609462860.0}

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        access_claims = tokens.get_access_claims_from_refresh(claims)
        expected_exp = date_mock + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        assert access_claims == {'sub': 'sub', 'iat': date_mock, 'exp': expected_exp,
                                 'refresh_iat': 1609462860.0}


class TestEncodeClaims:
    def test_encode_claims(self, settings):
        claims = {'sub': 'sub'}
        expected = pyjwt.encode(claims, 'test key')
        jwt = tokens.encode_claims(claims)
        assert jwt == expected
