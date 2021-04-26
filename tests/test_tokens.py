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
import pytz
import jwt as pyjwt
from datetime import timedelta
import djwto.tokens as tokens

from django.contrib.auth.models import User


class TestDefaultProcessClaims:
    def test_default_process_claims_raises(self, settings, rf):
        alice = None
        settings.DJWTO_ISS_CLAIM = 1
        request = rf.post('')
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Issuer must be str. Received int instead.'
        )
        settings.DJWTO_ISS_CLAIM = None

        settings.DJWTO_SUB_CLAIM = 1
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Subject must be str. Received int instead.'
        )
        settings.DJWTO_SUB_CLAIM = None

        settings.DJWTO_AUD_CLAIM = 1
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Audience must be either List[str] or str. Received int instead.'
        )

        settings.DJWTO_AUD_CLAIM = ['1', 1]
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Value of Audience must be either List[str] or str. '
            'Received List[list] instead.'
        )
        settings.DJWTO_AUD_CLAIM = None

        settings.DJWTO_REFRESH_TOKEN_LIFETIME = 1
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Refresh token lifetime must be a `timedelta` object.'
        )
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(minutes=-1)
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.default_process_claims(alice, request)
        assert exec_info.value.args[0] == (
            'Refresh token expiration time must be positive.'
        )

    @pytest.mark.django_db
    def test_default_process_claims(self, settings, rf, monkeypatch):
        date_mock = mock.Mock()
        uuid_mock = mock.Mock()

        date_mock.return_value = 1
        uuid_mock.uuid4.return_value = 'uuid'

        settings.DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(seconds=1)
        settings.DJWTO_NBF_LIFETIME = timedelta(seconds=1)
        settings.DJWTO_ISS_CLAIM = 'iss'
        settings.DJWTO_SUB_CLAIM = 'sub'
        settings.DJWTO_AUD_CLAIM = 'aud'

        monkeypatch.setattr('djwto.tokens.get_current_tz_unix_time', date_mock)
        monkeypatch.setattr('djwto.tokens.uuid', uuid_mock)
        alice = User.objects.get(username='alice')
        request = rf.post('')
        result = tokens.default_process_claims(alice, request)
        assert result == {
            'iss': 'iss',
            'sub': 'sub',
            'aud': 'aud',
            'iat': 1,
            'exp': 2.0,
            'nbf': 2.0,
            'jti': 'uuid',
            'username': 'alice',
            'user_id': 1
        }


class TestGetCurrentTzUnixTime:
    def test_get_current_tz_unix_time_raises(self, settings):
        settings.TIME_ZONE = 'test_tz'
        with pytest.raises(ValueError) as exec_info:
            _ = tokens.get_current_tz_unix_time()
        assert exec_info.value.args[0] == (
            'Value test_tz is not valid. Run `import pytz; pytz.all_timezones for a '
            'list of valid values.'
        )

    def test_get_current_tz_unix_time(self, settings, monkeypatch):
        tz = 'UTC'
        settings.TIME_ZONE = tz
        date_mock = mock.Mock()
        date_mock.now.return_value.timestamp.return_value = 1
        monkeypatch.setattr('djwto.tokens.datetime', date_mock)
        result = tokens.get_current_tz_unix_time()
        assert result == 1
        date_mock.now.assert_called_with(pytz.timezone(tz))

        settings.USE_TZ = False
        tz = 'GMT'
        settings.TIME_ZONE = tz
        result = tokens.get_current_tz_unix_time()
        assert result == 1
        date_mock.now.assert_called_with(pytz.timezone('UTC'))


class TestGetAccessClaimsFromRefresh:
    def test_get_access_from_refresh_raises(self, settings):
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(seconds=-1)
        with pytest.raises(ValueError):
            _ = tokens.get_access_claims_from_refresh({})

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = 1
        with pytest.raises(ValueError):
            _ = tokens.get_access_claims_from_refresh({})

    def test_get_access_from_refresh(self, settings, monkeypatch):
        claims = {'sub': 'sub'}
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = None
        settings.DJWTO_IAT_CLAIM = False
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub'}

        date_mock = mock.Mock()
        date_mock.return_value = 1
        monkeypatch.setattr('djwto.tokens.get_current_tz_unix_time', date_mock)
        settings.DJWTO_IAT_CLAIM = True
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub', 'iat': 1}

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(seconds=1)
        access_claims = tokens.get_access_claims_from_refresh(claims)
        assert access_claims == {'sub': 'sub', 'iat': 1, 'exp': 2}


class TestEncodeClaims:
    def test_encode_claims(self, settings):
        claims = {'sub': 'sub'}
        expected = pyjwt.encode(claims, 'test key')
        jwt = tokens.encode_claims(claims)
        assert jwt == expected
