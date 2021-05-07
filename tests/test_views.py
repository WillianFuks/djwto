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
from importlib import reload

import jwt as pyjwt
import mock
import pytest

import djwto.views as views
from djwto.authentication import WWWAUTHENTICATE
from djwto.exceptions import JWTValidationError
from djwto.models import JWTBlacklist
from django.middleware.csrf import get_token


@pytest.mark.django_db
class TestGetTokensView:
    CTPL = ('Set-Cookie: {name}={value}; expires={expires}; {http_only}'
            'Max-Age={max_age}; Path={path}; SameSite={samesite}; {secure}')
    VTPL = (
        '"{{\\"exp\\": \\"{exp}\\"\\054 \\"iat\\": \\"{iat}\\"\\054 \\"jti\\": '
        '\\"uuid\\"\\054 \\"nbf\\": \\"{nbf}\\"\\054 \\"refresh_iat\\": {refresh_iat}'
        '\\054 \\"user_id\\": 1\\054 \\"username\\": \\"alice\\"}}"'
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
        'username': 'alice',
        'user_id': 1,
        'refresh_iat': timegm(date_.utctimetuple())
    }
    expected_access_jwt = pyjwt.encode(expected_access_claims, sign_key)

    expected_refresh_claims = {
        'iat': date_,
        'exp': date_ + refresh_lifetime,
        'nbf': date_ + nbf_lifetime,
        'jti': 'uuid',
        'username': 'alice',
        'user_id': 1
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

    def test_post_one_cookie_mode_with_csrf(self, rf, settings, monkeypatch):
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

    def test_post_one_cookie_mode_without_csrf(self, rf, settings, monkeypatch):
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

    def test_post_two_cookies_mode_with_csrf(self, rf, settings, monkeypatch):
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
            refresh_iat=timegm(self.date_.utctimetuple())
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

    def test_post_two_cookies_mode_without_csrf(self, rf, settings, monkeypatch):
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
            refresh_iat=timegm(self.date_.utctimetuple())
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


@pytest.mark.django_db
class TestBlacklistTokensView:
    sign_key = 'test'

    def test_post_returns_error_response(self, rf, settings, monkeypatch):
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView
        # Blacklist endpoint defined in a URL that does not contain the path of the
        # refresh cookie. This case should fail as no refresh cookie can be retrieved
        # for blacklisting
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        request = rf.post('/api/tokens')
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Only the refresh token can be blacklisted. The URL endpoint for'
            b' blacklisting must contain the value set in '
            b'`settings.DJWTO_REFRESH_COOKIE_PATH`."}'
        )
        assert response.status_code == 403

        # If settings do not define JTI claim then the Blacklist API cannot be used
        settings.DJWTO_JTI_CLAIM = False
        request = rf.post('/api/tokens/refresh')
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Value of `settings.DJWTO_JTI_CLAIM` must be `True` in order to '
            b'use Blacklist."}'
        )
        assert response.status_code == 403

        # Input POST request must contain a data field such as "-d jwt_type=refresh"
        settings.DJWTO_JTI_CLAIM = True
        request = rf.post('/api/tokens/refresh', {'jwt_type': ''})
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Field \\"jwt_type=refresh\\" must be sent in request."}'
        )
        assert response.status_code == 403

        request = rf.post('/api/tokens/refresh', {'jwt_type': 'access'})
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "Field \\"jwt_type=refresh\\" must be sent in request."}'
        )
        assert response.status_code == 403

        # If a JWT validation error occurs no token can be blacklisted. This ensures
        # authenticity of the income request
        get_mock = mock.Mock(side_effect=JWTValidationError('test msg'))
        monkeypatch.setattr(
            'djwto.views.auth.JWTAuthentication.get_raw_token_from_request', get_mock)
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "test msg"}'
        )
        assert response.status_code == 403

        # If input token doesn't have JTI claim then it fails to blacklist
        get_mock = mock.Mock(return_value='token')
        val_mock = mock.Mock(return_value={})
        monkeypatch.setattr(
            'djwto.views.auth.JWTAuthentication.get_raw_token_from_request', get_mock)
        monkeypatch.setattr(
            'djwto.views.auth.JWTAuthentication.validate_token', val_mock)

        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = BlackListTokenView.as_view()(request)
        assert response.content == (
            b'{"error": "No jti claim was available in the input token. The value is '
            b'mandatoryin order to use the Blacklist api."}'
        )
        assert response.status_code == 403

        # Tokens that have already been blacklisted cannot be blacklisted again
        get_mock = mock.Mock(return_value='token')
        val_mock = mock.Mock(return_value={'jti': '1'})
        monkeypatch.setattr(
            'djwto.views.auth.JWTAuthentication.get_raw_token_from_request', get_mock)
        monkeypatch.setattr(
            'djwto.views.auth.JWTAuthentication.validate_token', val_mock)

        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
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

    def test_post_json_mode_with_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'jti': '2', 'exp': exp}
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

    def test_post_json_mode_without_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'JSON'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'jti': '2', 'exp': exp}
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

    def test_post_one_cookie_mode_with_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3'}
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
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access'])

    def test_post_one_cookie_mode_without_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3'}
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
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access'])

    def test_post_two_cookies_mode_with_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = True
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        expected_payload = {'jti': '4'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'value access payload'
        rf.cookies['jwt_access_signature'] = 'value access signature'
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
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_payload'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_signature'])

    def test_post_two_cookies_mode_without_csrf(self, rf, settings, monkeypatch):
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_CSRF = False
        reload(views)
        from djwto.views import BlackListTokenView

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '3'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'value access'
        expected_payload = {'jti': '4'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'value access payload'
        rf.cookies['jwt_access_signature'] = 'value access signature'
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
        assert 'Max-Age=0' in str(response.cookies['jwt_refresh'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_payload'])
        assert 'Max-Age=0' in str(response.cookies['jwt_access_signature'])
