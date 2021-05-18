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
from calendar import timegm
import djwto.tokens as tokens
from importlib import reload

import jwt as pyjwt
import mock
import pytest

import djwto.views as views
import djwto.signals as signals
from djwto.authentication import WWWAUTHENTICATE
from djwto.models import JWTBlacklist
from django.middleware.csrf import get_token
from django.http.response import JsonResponse


@pytest.mark.django_db
class TestGetTokensView:
    CTPL = ('Set-Cookie: {name}={value}; expires={expires}; {http_only}'
            'Max-Age={max_age}; Path={path}; SameSite={samesite}; {secure}')

    VTPL = (
        '"{{\\"exp\\": \\"{exp}\\"\\054 \\"iat\\": \\"{iat}\\"\\054 \\"jti\\": '
        '\\"uuid\\"\\054 \\"nbf\\": \\"{nbf}\\"\\054 \\"refresh_iat\\": {refresh_iat}'
        '\\054 \\"type\\": \\"{type_}\\"\\054 \\"user\\": {{\\"id\\": {user_id}'
        '\\054 \\"username\\": \\"{username}\\"}}}}"'
    )
    # Test JSON mode creates the token as expected
    date_ = datetime(2021, 1, 1)
    d_mock = mock.Mock()
    d_mock.utcnow.return_value = date_

    uuid_ = 'uuid'
    uuid_mock = mock.Mock()
    uuid_mock.uuid4.return_value = uuid_

    sign_key = 'test'
    refresh_lifetime = timedelta(days=1)
    access_lifetime = timedelta(hours=1)
    nbf_lifetime = timedelta(minutes=1)

    expected_access_claims = {
        'iat': date_,
        'exp': date_ + access_lifetime,
        'nbf': date_ + nbf_lifetime,
        'jti': 'uuid',
        'type': 'access',
        'user': {
            'username': 'alice',
            'id': 1,
        },
        'refresh_iat': timegm(date_.utctimetuple())
    }
    expected_access_jwt = pyjwt.encode(expected_access_claims, sign_key)

    expected_refresh_claims = {
        'iat': date_,
        'exp': date_ + refresh_lifetime,
        'nbf': date_ + nbf_lifetime,
        'jti': 'uuid',
        'type': 'refresh',
        'user': {
            'username': 'alice',
            'id': 1
        }
    }
    expected_refresh_jwt = pyjwt.encode(expected_refresh_claims, sign_key)

    def test_post_with_invalid_user_data(self, rf):
        # Force a reload as djwto sets the code according to the values available in
        # `settings`, i.e., if CSRF protection is enabled then the methods are decorated
        # with specific functions.
        reload(views)
        from djwto.views import GetTokensView

        # Invalid password
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pasas'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "{\\"__all__\\": [\\"Please enter a correct username and '
            b'password. Note that both fields may be case-sensitive.\\"]}"}'
        )
        assert response.headers['WWW-Authenticate'] == WWWAUTHENTICATE

        # Empty input
        request = rf.post('/api/tokens', {'username': '', 'password': ''})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "{\\"username\\": [\\"This field is required.\\"], '
            b'\\"password\\": [\\"This field is required.\\"]}"}'
        )
        assert response.headers['WWW-Authenticate'] == WWWAUTHENTICATE

    def test_post_with_wrong_settings_raises(self, rf, settings):
        reload(views)
        from djwto.views import GetTokensView

        # Issuer must be string
        settings.DJWTO_ISS_CLAIM = 1
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_ISS_CLAIM = None

        # Subject must be string
        settings.DJWTO_SUB_CLAIM = 1
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_SUB_CLAIM = None

        # Audience must be string
        settings.DJWTO_AUD_CLAIM = 1
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_AUD_CLAIM = None

        # Tokens lifetime must be defined as positive timedeltas
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = 1
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500

        settings.DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(days=-1)
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = None

        settings.DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(days=-1)
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = None

        settings.DJWTO_NBF_LIFETIME = timedelta(days=-1)
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500
        settings.DJWTO_NBF_LIFETIME = None

        # Mode can only be 'JSON', 'ONE-COOKIE' or 'TWO-COOKIES'
        settings.DJWTO_MODE = 'invalid test mode'
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to process request."}'
        )
        assert response.status_code == 500

    def test_post_json_mode(self, rf, settings, monkeypatch):
        # First set `settings.DJWTO_MODE` properly so when `GetTokensView` is imported
        # the `_build_decorator` uses the proper function
        settings.DJWTO_MODE = 'JSON'
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        # Repeteadly sets `settings` locally to guarantee values are as expected
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)

        assert response.content == (
            f'{{"refresh": "{self.expected_refresh_jwt}", '
            f'"access": "{self.expected_access_jwt}"}}'
        ).encode()

        # Tests scenario where JWT is available in request. This case should return
        # a 200 status code with no changes in the backend
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JIT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"msg": "User already authenticated."}'

    def test_post_json_mode_sends_signal_on_success(self, rf, settings, monkeypatch):
        # First set `settings.DJWTO_MODE` properly so when `GetTokensView` is imported
        # the `_build_decorator` uses the proper function
        settings.DJWTO_MODE = 'JSON'
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        # Repeteadly sets `settings` locally to guarantee values are as expected
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        handler = mock.Mock()
        signals.jwt_logged_in.connect(handler, sender='GetTokensView')

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        _ = GetTokensView.as_view()(request)
        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'refresh_claims',
                                     'access_claims']
        assert call['sender'] == 'GetTokensView'

    def test_post_json_mode_sends_signal_on_failure(self, rf):
        reload(views)
        from djwto.views import GetTokensView

        handler = mock.Mock()
        signals.jwt_login_fail.connect(handler, sender='GetTokensView')

        # Invalid password
        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pasas'})
        _ = GetTokensView.as_view()(request)

        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'error']
        assert call['sender'] == 'GetTokensView'
        assert '__all__' in call['error']

    def test_post_json_mode_sends_signal_on_settings_failure(self, rf, settings):
        reload(views)
        from djwto.views import GetTokensView

        settings.DJWTO_MODE = 'invalid'

        handler = mock.Mock()
        signals.jwt_login_fail.connect(handler, sender='GetTokensView')

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        _ = GetTokensView.as_view()(request)

        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'error']
        assert call['sender'] == 'GetTokensView'
        assert call['error'] == (
            'settings.DJWTO_MODE must be either "JSON", "ONE-COOKIE" or "TWO-COOKIES".'
            'Received "invalid" instead.'
        )

    def test_post_one_cookie_mode_ensuring_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        now = datetime.now()
        refresh_expires = (now +
                           self.refresh_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(refresh) == self.CTPL.format(
            name='jwt_refresh',
            value=self.expected_refresh_jwt,
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(self.refresh_lifetime.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )
        assert 'csrftoken' in cookies

        access = cookies['jwt_access']
        access_expires = (now +
                          self.access_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(access) == self.CTPL.format(
            name='jwt_access',
            value=self.expected_access_jwt,
            expires=access_expires,
            http_only='HttpOnly; ',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        # Tests scenario where JWT are available in request. This case should return
        # a 200 status code with no changes in the backend
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JIT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/token')
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"msg": "User already authenticated."}'

    def test_post_one_cookie_mode_not_ensuring_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        now = datetime.now()
        refresh_expires = (now +
                           self.refresh_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(refresh) == self.CTPL.format(
            name='jwt_refresh',
            value=self.expected_refresh_jwt,
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(self.refresh_lifetime.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )
        assert 'csrftoken' not in cookies

        access = cookies['jwt_access']
        access_expires = (now +
                          self.access_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(access) == self.CTPL.format(
            name='jwt_access',
            value=self.expected_access_jwt,
            expires=access_expires,
            http_only='HttpOnly; ',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        # Tests scenario where JWT are available in request. This case should return
        # a 200 status code with no changes in the backend
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JIT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/token')
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"msg": "User already authenticated."}'

    def test_post_two_cookies_mode_ensuring_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        now = datetime.now()
        refresh_expires = (now +
                           self.refresh_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")

        assert 'csrftoken' in cookies

        assert str(refresh) == self.CTPL.format(
            name='jwt_refresh',
            value=self.expected_refresh_jwt,
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(self.refresh_lifetime.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        value = self.VTPL.format(
            exp=(self.date_ + self.access_lifetime).strftime("%Y-%m-%dT%H:%M:%S"),
            iat=self.date_.strftime("%Y-%m-%dT%H:%M:%S"),
            nbf=(self.date_ + self.nbf_lifetime).strftime("%Y-%m-%dT%H:%M:%S"),
            refresh_iat=timegm(self.date_.utctimetuple()),
            type_='access',
            user_id=1,
            username='alice'
        )

        access_payload = cookies['jwt_access_payload']
        access_expires = (now +
                          self.access_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert str(access_payload) == self.CTPL.format(
            name='jwt_access_payload',
            value=value,
            expires=access_expires,
            http_only='',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        access_signature = cookies['jwt_access_token']
        assert str(access_signature) == self.CTPL.format(
            name='jwt_access_token',
            value=self.expected_access_jwt,
            expires=access_expires,
            http_only='HttpOnly; ',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        # Tests scenario where JWT are available in request. This case should return
        # a 200 status code with no changes in the backend
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JIT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_access_token'] = expected_jwt
        request = rf.post('/api/token')
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"msg": "User already authenticated."}'

    def test_post_two_cookies_mode_not_ensuring_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import GetTokensView

        monkeypatch.setattr('djwto.views.tokens.datetime', self.d_mock)
        monkeypatch.setattr('djwto.views.tokens.uuid', self.uuid_mock)

        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_TOKEN_LIFETIME = self.refresh_lifetime
        settings.DJWTO_ACCESS_TOKEN_LIFETIME = self.access_lifetime
        settings.DJWTO_NBF_LIFETIME = self.nbf_lifetime

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        response = GetTokensView.as_view()(request)
        cookies = dict(response.cookies)
        refresh = cookies['jwt_refresh']
        now = datetime.now()
        refresh_expires = (now +
                           self.refresh_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")

        assert 'csrftoken' not in cookies

        print(str(refresh), '\n')
        print(self.CTPL.format(
            name='jwt_refresh',
            value=self.expected_refresh_jwt,
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(self.refresh_lifetime.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        ))

        assert str(refresh) == self.CTPL.format(
            name='jwt_refresh',
            value=self.expected_refresh_jwt,
            expires=refresh_expires,
            http_only='HttpOnly; ',
            max_age=int(self.refresh_lifetime.total_seconds()),
            path=settings.DJWTO_REFRESH_COOKIE_PATH,
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        value = self.VTPL.format(
            exp=(self.date_ + self.access_lifetime).strftime("%Y-%m-%dT%H:%M:%S"),
            iat=self.date_.strftime("%Y-%m-%dT%H:%M:%S"),
            nbf=(self.date_ + self.nbf_lifetime).strftime("%Y-%m-%dT%H:%M:%S"),
            refresh_iat=timegm(self.date_.utctimetuple()),
            type_='access',
            user_id=1,
            username='alice'
        )

        access_payload = cookies['jwt_access_payload']
        access_expires = (now +
                          self.access_lifetime).strftime("%a, %d %b %Y %H:%M:%S GMT")

        assert str(access_payload) == self.CTPL.format(
            name='jwt_access_payload',
            value=value,
            expires=access_expires,
            http_only='',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        access_token = cookies['jwt_access_token']
        assert str(access_token) == self.CTPL.format(
            name='jwt_access_token',
            value=self.expected_access_jwt,
            expires=access_expires,
            http_only='HttpOnly; ',
            max_age=int(self.access_lifetime.total_seconds()),
            path='/',
            samesite=settings.DJWTO_SAME_SITE,
            secure='Secure'
        )

        # Tests scenario where JWT are available in request. This case should return
        # a 200 status code with no changes in the backend
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JIT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_access_token'] = expected_jwt
        request = rf.post('/api/token')
        response = GetTokensView.as_view()(request)
        assert response.content == b'{"msg": "User already authenticated."}'


@pytest.mark.django_db
class TestBlacklistTokensView:
    sign_key = 'test'

    def test_post_returns_error_response(self, rf, settings):
        reload(views)
        from djwto.views import BlackListTokenView
        # Blacklist endpoint defined in a URL that does not contain the path of the
        # refresh cookie. This case should fail as no refresh cookie can be retrieved
        # for blacklisting
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        request = rf.post('/api/tokens')
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Token not found in \\"HTTP_AUTHORIZATION\\" header."}'
        )

        # Simulates user logged-in
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'access'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh token was not sent in authorization header."}'
        )
        assert response.status_code == 403

        # If input token doesn't have JTI claim then it fails to blacklist
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "No jti claim was available in the input token. The value is '
            b'mandatory in order to use the Blacklist API."}'
        )
        assert response.status_code == 403

        # Tokens that have already been blacklisted cannot be blacklisted again
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'jti': '1', 'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Input jti token is already blacklisted."}'
        )
        assert response.status_code == 409

        # Test view is protected by CSRF
        settings.DJWTO_CSRF = True
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        reload(views)
        from djwto.views import BlackListTokenView

        request = rf.post('/api/tokens/refresh')
        response = BlackListTokenView.as_view()(request)
        assert b'Forbidden' in response.content
        assert response.status_code == 403

    def test_post_json_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'jti': '2', 'exp': exp, 'user': {'username': 'alice',
                            'id': 1}, 'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='2').exists()
        obj = JWTBlacklist.objects.get(jti='2')
        assert obj.jti == '2'
        assert obj.token == expected_jwt
        exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
        assert obj.expires.strftime("%Y-%m-%d %H:%M:%S") == exp_str

    def test_post_json_mode_with_csrf_sends_signal(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        handler = mock.Mock()
        signals.jwt_blacklisted.connect(handler, sender='BlackListTokenView')

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'jti': '2', 'exp': exp, 'user': {'username': 'alice',
                            'id': 1}, 'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        _ = BlackListTokenView.as_view()(request)

        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'jti']
        assert call['sender'] == 'BlackListTokenView'

    def test_delete_json_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.delete('/api/tokens/refresh')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "No token to delete."}'
        )

    def test_post_json_mode_without_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'jti': '2', 'exp': exp, 'user': {'username': 'alice',
                            'id': 1}, 'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='2').exists()
        obj = JWTBlacklist.objects.get(jti='2')
        assert obj.jti == '2'
        assert obj.token == expected_jwt
        exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
        assert obj.expires.strftime("%Y-%m-%d %H:%M:%S") == exp_str

    def test_post_one_cookie_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3', 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='3').exists()
        obj = JWTBlacklist.objects.get(jti='3')
        assert obj.jti == '3'
        assert obj.token == expected_jwt
        assert obj.expires is None

    def test_delete_one_cookie_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.delete('/api/tokens')
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "Tokens successfully deleted."}'
        )
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access'])

    def test_post_one_cookie_mode_without_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3', 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='3').exists()
        obj = JWTBlacklist.objects.get(jti='3')
        assert obj.jti == '3'
        assert obj.token == expected_jwt
        assert obj.expires is None

    def test_post_two_cookies_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '4', 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'value access payload'
        rf.cookies['jwt_access_token'] = 'value access token'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = BlackListTokenView.as_view()(request)

        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='4').exists()
        obj = JWTBlacklist.objects.get(jti='4')
        assert obj.jti == '4'
        assert obj.token == expected_jwt
        assert obj.expires is None

    def test_delete_two_cookies_mode_with_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = expected_payload
        rf.cookies['jwt_access_token'] = expected_jwt
        request = rf.delete('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = BlackListTokenView.as_view()(request)

        assert response.content == (
            b'{"message": "Tokens successfully deleted."}'
        )
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_payload'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_token'])

    def test_post_two_cookies_mode_without_csrf(self, rf, settings):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '4', 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'value access payload'
        rf.cookies['jwt_access_token'] = 'value access token'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = BlackListTokenView.as_view()(request)

        assert response.content == (
            b'{"message": "Token successfully blacklisted."}'
        )
        assert JWTBlacklist.objects.all().count() == 2
        assert JWTBlacklist.objects.filter(jti='4').exists()
        obj = JWTBlacklist.objects.get(jti='4')
        assert obj.jti == '4'
        assert obj.token == expected_jwt
        assert obj.expires is None


class TestValidateTokensView:
    sign_key = 'test'

    def test_post_returns_error_response(self, rf, settings):
        reload(views)
        from djwto.views import ValidateTokensView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        request = rf.post('/api/tokens')
        response = ValidateTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Token not found in \\"HTTP_AUTHORIZATION\\" header."}'
        )

        # Invalid JWT
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=-1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = ValidateTokensView.as_view()(request)
        assert response.content == (
            b'{"error": "Signature has expired"}'
        )
        assert response.status_code == 403

        # Test view is protected by CSRF
        settings.DJWTO_CSRF = True
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        reload(views)
        from djwto.views import ValidateTokensView

        request = rf.post('/api/tokens/refresh')
        response = ValidateTokensView.as_view()(request)
        assert b'Forbidden' in response.content
        assert response.status_code == 403

        # Invalid JWT Cookie
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import ValidateTokensView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=-1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = ValidateTokensView.as_view()(request)
        assert response.content == b'{"error": "Signature has expired"}'

    def test_post(self, rf, settings):
        reload(views)
        from djwto.views import ValidateTokensView

        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = ValidateTokensView.as_view()(request)
        assert response.content == (
            b'{"msg": "Token is valid"}'
        )

        # ONE-COOOKIE Mode
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import ValidateTokensView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'refresh'
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/tokens')
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = ValidateTokensView.as_view()(request)
        assert response.content == (
            b'{"msg": "Token is valid"}'
        )

        # TWO-COOKIES Mode
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import ValidateTokensView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'value access payload'
        rf.cookies['jwt_access_token'] = 'value access token'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = ValidateTokensView.as_view()(request)
        assert response.content == (
            b'{"msg": "Token is valid"}'
        )

    def test_post_sends_signal(self, rf, settings):
        reload(views)
        from djwto.views import ValidateTokensView

        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        handler = mock.Mock()
        signals.jwt_token_validated.connect(handler, sender='ValidateTokensView')

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        _ = ValidateTokensView.as_view()(request)

        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request']
        assert call['sender'] == 'ValidateTokensView'


class TestRefreshAccessView:
    sign_key = 'test'

    def test_post_returns_error_response(self, rf, settings):
        # Test view is protected by CSRF
        settings.DJWTO_CSRF = True
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        reload(views)
        from djwto.views import RefreshAccessView

        request = rf.post('/api/tokens/refresh')
        response = RefreshAccessView.as_view()(request)
        assert b'Forbidden' in response.content
        assert response.status_code == 403

        # Invalid JWT Cookie
        reload(views)
        from djwto.views import RefreshAccessView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=-1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = RefreshAccessView.as_view()(request)
        assert response.content == b'{"error": "Signature has expired"}'

    def test_post(self, rf, settings, monkeypatch, date_mock):
        reload(views)
        from djwto.views import RefreshAccessView

        build_mock = mock.Mock()
        build_mock.return_value = 'worked'
        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.views.build_tokens_response', build_mock)
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)

        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_payload = tokens.decode_token(expected_jwt)

        expected_access_payload = expected_payload.copy()
        expected_access_payload['exp'] = date_mock + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        expected_access_payload['type'] = 'access'

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = RefreshAccessView.as_view()(request)
        assert response == 'worked'
        build_mock.assert_any_call(expected_payload, expected_access_payload)

        # ONE-COOOKIE Mode
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import RefreshAccessView

        build_mock = mock.Mock()
        build_mock.return_value = JsonResponse({})
        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.views.build_tokens_response', build_mock)
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'access'
        request = rf.post('/api/tokens', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = RefreshAccessView.as_view()(request)
        assert response.content == b'{}'
        build_mock.assert_any_call(expected_payload, expected_access_payload)

        # TWO-COOOKIES Mode
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import RefreshAccessView

        build_mock = mock.Mock()
        build_mock.return_value = JsonResponse({})
        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.views.build_tokens_response', build_mock)
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'access payload'
        rf.cookies['jwt_access_token'] = 'access token'
        request = rf.post('/api/tokens', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = RefreshAccessView.as_view()(request)
        assert response.content == b'{}'
        build_mock.assert_any_call(expected_payload, expected_access_payload)

    def test_post_sends_signal(self, rf, settings, monkeypatch, date_mock):
        reload(views)
        from djwto.views import RefreshAccessView

        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        handler = mock.Mock()
        signals.jwt_access_refreshed.connect(handler, sender='RefreshAccessView')

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        _ = RefreshAccessView.as_view()(request)

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        _ = RefreshAccessView.as_view()(request)
        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'refresh_claims',
                                     'access_claims']
        assert call['sender'] == 'RefreshAccessView'


@pytest.mark.django_db
class TestUpdateRefreshView:
    sign_key = 'test'

    def test_post_returns_error_response(self, rf, settings):
        # Test view is protected by CSRF
        settings.DJWTO_CSRF = True
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        reload(views)
        from djwto.views import UpdateRefreshView

        request = rf.post('/api/tokens/refresh')
        response = UpdateRefreshView.as_view()(request)
        assert b'Forbidden' in response.content
        assert response.status_code == 403

        # Invalid JWT Cookie
        reload(views)
        from djwto.views import UpdateRefreshView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=-1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        csrf_token = get_token(request)
        request.COOKIES['csrftoken'] = csrf_token
        request.META['HTTP_X_CSRFTOKEN'] = csrf_token
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "Signature has expired"}'

    def test_post_settings_refresh_update(self, rf, settings, monkeypatch):
        reload(views)
        from djwto.views import UpdateRefreshView

        # JSON Mode Disabled Refresh
        settings.DJWTO_ALLOW_REFRESH_UPDATE = False
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh', 'jti': '1'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "Can\'t update refresh token."}'

        # Enable Refresh and JTI
        settings.DJWTO_ALLOW_REFRESH_UPDATE = True
        settings.DJWTO_JTI_CLAIM = True
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "Can\'t update refresh token."}'

    def test_post_sends_signal(self, rf, settings, monkeypatch):
        reload(views)
        from djwto.views import UpdateRefreshView

        # JSON Mode Disabled Refresh
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_ALLOW_REFRESH_UPDATE = True
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_IAT_CLAIM = False
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        handler = mock.Mock()
        signals.jwt_refresh_updated.connect(handler, sender='UpdateRefreshView')

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        _ = UpdateRefreshView.as_view()(request)

        request = rf.post('/api/tokens', {'username': 'alice', 'password': 'pass'})
        _ = UpdateRefreshView.as_view()(request)
        call = handler.call_args.kwargs
        assert list(call.keys()) == ['signal', 'sender', 'request', 'refresh_claims',
                                     'access_claims']
        assert call['sender'] == 'UpdateRefreshView'

    def test_post_blacklist_jti(self, rf, settings, monkeypatch, date_mock):
        reload(views)
        from djwto.views import UpdateRefreshView

        build_mock = mock.Mock()
        build_mock.return_value = 'worked'
        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.views.build_tokens_response', build_mock)
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)
        monkeypatch.setattr('djwto.views.datetime', d_mock)

        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh', 'jti': '1'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_payload = tokens.decode_token(expected_jwt)

        # Enable Refresh and JTI
        settings.DJWTO_ALLOW_REFRESH_UPDATE = True
        settings.DJWTO_JTI_CLAIM = True
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "Can\'t update refresh token."}'

        # Token is not blacklisted now
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh', 'jti': '2'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_payload = tokens.decode_token(expected_jwt)

        expected_access_payload = expected_payload.copy()
        expected_access_payload['exp'] = date_mock + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        expected_access_payload['type'] = 'access'

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)

        expected_payload['exp'] = date_mock + settings.DJWTO_REFRESH_TOKEN_LIFETIME
        build_mock.assert_any_call(expected_payload, expected_access_payload)

        # Add IAT
        settings.DJWTO_IAT_CLAIM = True
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh', 'jti': '2', 'iat': date_mock}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_payload = tokens.decode_token(expected_jwt)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        expected_payload['exp'] = date_mock + settings.DJWTO_REFRESH_TOKEN_LIFETIME
        expected_payload['iat'] = date_mock
        expected_access_payload['iat'] = date_mock
        expected_access_payload['refresh_iat'] = timegm(date_mock.utctimetuple())

        response = UpdateRefreshView.as_view()(request)
        build_mock.assert_any_call(expected_payload, expected_access_payload)

    def test_post_user_errors(self, rf, settings, monkeypatch, date_mock):
        reload(views)
        from djwto.views import UpdateRefreshView

        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = timegm((datetime.now() + timedelta(days=1)).utctimetuple())
        expected_payload = {'exp': exp, 'user': {'username': 'bob', 'id': 2},
                            'type': 'refresh', 'jti': '2'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        # User is not active
        settings.DJWTO_ALLOW_REFRESH_UPDATE = True
        settings.DJWTO_JTI_CLAIM = False
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "User is inactive."}'

        # User doesn't exist
        expected_payload = {'exp': exp, 'user': {'username': 'claire', 'id': 3},
                            'type': 'refresh', 'jti': '2'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        assert response.content == b'{"error": "Can\'t update refresh token."}'

        # Scenario where user is not saved in token
        settings.DJWTO_IAT_CLAIM = False
        import djwto.authentication as auth
        import djwto.tokens as tokens

        backup = auth.jwt_login_required

        # Ugly hack to change jwt_login_required
        def mock_test_func(request):
            token = auth.get_raw_token_from_request(request)
            payload = tokens.decode_token(token)
            request.payload = payload
            request.token = token
            return True, ''

        def mock_jwt_login_required(view_func):
            return auth.jwt_passes_test(mock_test_func)(view_func)

        auth.jwt_login_required = mock_jwt_login_required

        reload(views)
        from djwto.views import UpdateRefreshView

        build_mock = mock.Mock()
        build_mock.return_value = 'worked'
        d_mock = mock.Mock()
        d_mock.utcnow.return_value = date_mock
        monkeypatch.setattr('djwto.views.build_tokens_response', build_mock)
        monkeypatch.setattr('djwto.tokens.datetime', d_mock)
        monkeypatch.setattr('djwto.views.datetime', d_mock)

        expected_payload = {'exp': exp, 'type': 'refresh', 'jti': '2'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        expected_payload = tokens.decode_token(expected_jwt)

        expected_access_payload = expected_payload.copy()
        expected_access_payload['exp'] = date_mock + settings.DJWTO_ACCESS_TOKEN_LIFETIME
        expected_access_payload['type'] = 'access'

        expected_payload['exp'] = date_mock + settings.DJWTO_REFRESH_TOKEN_LIFETIME

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = UpdateRefreshView.as_view()(request)
        build_mock.assert_any_call(expected_payload, expected_access_payload)
        auth.jwt_login_required = backup
