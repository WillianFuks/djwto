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


from datetime import datetime

import mock
import pytest

from djwto.views import GetTokensView


@pytest.mark.django_db
class TestGetTokensView:
    view = GetTokensView

    def test_post_with_invalid_user_data(self, rf):
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pasas'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"errors": {"__all__": ["Please enter a correct username and password. '
            b'Note that both fields may be case-sensitive."]}}'
        )

        request = rf.post('/api/tokens', {'username': '', 'password': ''})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"errors": {"username": ["This field is required."], "password": '
            b'["This field is required."]}}'
        )

    def test_post_with_wrong_mode_raises(self, rf, settings):
        settings.DJWTO_MODE = 'test'
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        with pytest.raises(ValueError) as exec_info:
            _ = GetTokensView.as_view()(request)
        assert exec_info.value.args[0] == (
            'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
            'Received "test" instead.'
        )

    def test_post(self, rf, settings, monkeypatch):
        CTPL = ('Set-Cookie: {name}={value}; expires={expires}; {http_only}'
                'Max-Age={max_age}; Path={path}; SameSite={samesite}; {secure}')
        encode_mock = mock.Mock()
        encode_mock.side_effect = ['refresh', 'access']
        monkeypatch.setattr('djwto.views.tokens.encode_claims', encode_mock)
        settings.DJWTO_MODE = 'JSON'
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"refresh": "refresh", "access": "access"}'

        encode_mock.side_effect = ['refresh', 'access']
        settings.DJWTO_MODE = 'ONE-COOKIE'
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        refresh_expires = datetime.now() + settings.DJWTO_REFRESH_TOKEN_LIFETIME
        refresh_expires = refresh_expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(refresh) == CTPL.format(
            name='jwt_refresh',
            value='refresh',
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(settings.DJWTO_REFRESH_TOKEN_LIFETIME.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        access = cookies['jwt_access']
        access_expires = datetime.now() + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        access_expires = access_expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(access) == CTPL.format(
            name='jwt_access',
            value='access',
            expires=access_expires,
            http_only='HttpOnly; ',
            max_age=int(settings.DJWTO_ACCESS_TOKEN_LIFETIME.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        get_a_mock = mock.Mock()
        av = {'v1': 't1'}
        get_a_mock.return_value = av
        monkeypatch.setattr('djwto.views.tokens.get_access_claims_from_refresh',
                            get_a_mock)
        settings.DJWTO_MODE = 'JSON'
        encode_mock.side_effect = ['refresh', 'abc.def.access']
        settings.DJWTO_MODE = 'TWO-COOKIES'
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        assert str(refresh) == CTPL.format(
            name='jwt_refresh',
            value='refresh',
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(settings.DJWTO_REFRESH_TOKEN_LIFETIME.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        access_payload = cookies['jwt_access_payload']
        print(access_payload)
        assert str(access_payload) == CTPL.format(
            name='jwt_access_payload',
            value='"{\\"v1\\": \\"t1\\"}"',
            expires=access_expires,
            http_only='',
            max_age=int(settings.DJWTO_ACCESS_TOKEN_LIFETIME.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )
