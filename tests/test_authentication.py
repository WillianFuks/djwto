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

import jwt as pyjwt
import mock
import pytest
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http.response import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View

import djwto.authentication as auth
from djwto.exceptions import JWTValidationError


class MockJWTLoginView(View):
    @method_decorator(auth.jwt_login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        assert request.token is not None
        assert request.payload is not None
        assert 'user' in request.payload
        return JsonResponse({'msg': 'worked'})


class MockJWTRefreshRequiredView(View):
    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_is_refresh)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        from django.conf import settings

        assert request.token is not None
        assert request.payload is not None
        assert request.payload['type'] == 'refresh'
        assert 'user' in request.payload
        if settings.DJWTO_MODE != 'JSON':
            assert settings.DJWTO_REFRESH_COOKIE_PATH in request.path
            assert request.POST.get('jwt_type') == 'refresh'
        return JsonResponse({'msg': 'worked'})


class MockJWTPermsRequiredViewWithLogin(View):
    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_perm_required(['perm1', 'perm2']))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        assert request.token is not None
        assert request.payload is not None
        jwt_perms = request.payload.get('user', {}).get('perms')
        assert jwt_perms is not None
        assert jwt_perms == ['perm1', 'perm2']
        return JsonResponse({'msg': 'worked'})


class MockJWTPermsRequiredViewWithoutLogin(View):
    @method_decorator(auth.jwt_perm_required(['perm1', 'perm2']))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class TestJWTPermsRequired:
    sign_key = 'test'

    def test_post_fails_with_perms_required(self, rf, settings):
        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {
            'exp': exp,
            'user': {'username': 'alice', 'id': 1, 'perms': ['perm1']}
        }
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTPermsRequiredViewWithLogin.as_view()(request)
        assert response.content == (
            b'{"error": "Insufficient Permissions."}'
        )

        # No user
        expected_payload = {
            'exp': exp,
            'user': {'username': 'alice', 'id': 1}
        }
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTPermsRequiredViewWithLogin.as_view()(request)
        assert response.content == (
            b'{"error": "Invalid permissions for jwt token."}'
        )

        # Not logged in first
        expected_payload = {
            'exp': exp,
            'user': {'username': 'alice', 'id': 1, 'perms': ['perm1', 'perm2']}
        }
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTPermsRequiredViewWithoutLogin.as_view()(request)
        assert response.content == (
            b'{"error": "Login must happen before evaluating permissions."}'
        )

    def test_post_with_perms_required(self, rf, settings):
        # JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {
            'exp': exp,
            'user': {'username': 'alice', 'id': 1, 'perms': ['perm1', 'perm2']}
        }
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTPermsRequiredViewWithLogin.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )


class TestJWTRefreshRequired:
    sign_key = 'test'

    def test_post_fails_with_refresh_required(self, rf, settings):
        # First test JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'access'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh token was not sent in authorization header."}'
        )

        # Test ONE-COOKIE Mode
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/tokens')
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh token is only sent in path: /api/tokens/refresh"}'
        )

        request = rf.post('/api/tokens/refresh')
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"error": "POST variable \\"jwt_type\\" must be equal to \\"refresh\\"."}'
        )

        # Test TWO-COOKIES Mode
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access_token'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'payload'
        request = rf.post('/api/tokens')
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh token is only sent in path: /api/tokens/refresh"}'
        )

        request = rf.post('/api/tokens/refresh')
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"error": "POST variable \\"jwt_type\\" must be equal to \\"refresh\\"."}'
        )

    def test_post_with_refresh_required(self, rf, settings):
        # First test JSON Mode
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )

        # Test ONE-COOKIE Mode
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access'] = 'access'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )

        # Test TWO-COOKIES Mode
        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1},
                            'type': 'refresh'}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = expected_jwt
        rf.cookies['jwt_access_payload'] = 'access payload'
        rf.cookies['jwt_access_token'] = 'access token'
        request = rf.post('/api/tokens/refresh', {'jwt_type': 'refresh'})
        response = MockJWTRefreshRequiredView.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )


class TestJWTLoginRequired:
    sign_key = 'test'

    def test_post_fails_with_login_required(self, rf, settings):
        request = rf.post('/api/tokens')
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Token not found in \\"HTTP_AUTHORIZATION\\" header."}'
        )

        settings.DJWTO_MODE = 'ONE-COOKIE'
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Cookie \\"jwt_access\\" cannot be empty."}'
        )

        # Tests refresh type with invalid URL path
        request = rf.post('/invalid_path', {'jwt_type': 'refresh'})
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh cookie is only sent in path \\"/api/token/refresh\\". '
            b'Requested path was: /invalid_path."}'
        )

        # Valid URL Path with empty refresh token
        request = rf.post('/api/token/refresh', {'jwt_type': 'refresh'})
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Cookie \\"jwt_refresh\\" cannot be empty."}'
        )

        # Access Token
        settings.DJWTO_MODE = 'TWO-COOKIES'
        request = rf.post('/api/token/refresh')
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Cookie \\"jwt_access_token\\" cannot be empty."}'
        )

        # Refresh Token Invalid URL Path
        settings.DJWTO_MODE = 'TWO-COOKIES'
        request = rf.post('/invalid_path', {'jwt_type': 'refresh'})
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Refresh cookie is only sent in path \\"/api/token/refresh\\". '
            b'Requested path was: /invalid_path."}'
        )

        # Valid URL Path with empty refresh token
        settings.DJWTO_MODE = 'TWO-COOKIES'
        request = rf.post('/api/token/refresh', {'jwt_type': 'refresh'})
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Cookie \\"jwt_refresh\\" cannot be empty."}'
        )

    def test_post_with_login_required(self, rf, settings):
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to validate token."}'
        )

        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        request = rf.post('/api/tokens')
        request.META['HTTP_AUTHORIZATION'] = f'Authorization: Bearer {expected_jwt}'
        response = MockJWTLoginView.as_view()(request)
        print(response.content)
        assert response.content == (
            b'{"msg": "worked"}'
        )

        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/tokens')
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"error": "Failed to validate token."}'
        )

        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access'] = expected_jwt
        request = rf.post('/api/tokens')
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )

        settings.DJWTO_MODE = 'TWO-COOKIES'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access_payload'] = expected_payload
        rf.cookies['jwt_access_token'] = expected_jwt
        request = rf.post('/api/tokens')
        response = MockJWTLoginView.as_view()(request)
        print(response.content)
        assert response.content == (
            b'{"error": "Failed to validate token."}'
        )

        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        rf.cookies['jwt_refresh'] = 'foo'
        rf.cookies['jwt_access_payload'] = expected_payload
        rf.cookies['jwt_access_token'] = expected_jwt
        request = rf.post('/api/tokens')
        response = MockJWTLoginView.as_view()(request)
        assert response.content == (
            b'{"msg": "worked"}'
        )


@pytest.mark.django_db
class TestUserAuthenticate:
    def test_user_authenticate(self, rf):
        request = rf.post('', {'username': 'alice', 'password': 'pass'})
        user = auth.user_authenticate(request)
        assert user.username == 'alice'

    def test_user_authenticate_invalid_data_raises(self, rf):
        request = rf.post('', {'username': '', 'password': 'pass'})
        with pytest.raises(ValidationError) as exec_info:
            _ = auth.user_authenticate(request)
        assert exec_info.value.args[0] == (
            '{"username": ["This field is required."]}'
        )

        request = rf.post('', {'username': 'alice', 'password': 'wrong pass'})
        with pytest.raises(ValidationError) as exec_info:
            _ = auth.user_authenticate(request)
        assert exec_info.value.args[0] == (
            '{"__all__": ["Please enter a correct username and password. Note that both '
            'fields may be case-sensitive."]}'
        )


class TestGetRawTokenFromRequest:
    def test_get_raw_token_from_request_raises(self, rf, settings):
        request = rf.post('')
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Token not found in "HTTP_AUTHORIZATION" header.'
        )

        request.META['HTTP_AUTHORIZATION'] = 'Authorization: Bearer '
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Value in HTTP_AUTHORIZATION header is not valid.'
        )

        settings.DJWTO_MODE = 'ONE-COOKIE'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Cookie "jwt_access" cannot be empty.'
        )

        request.COOKIES['jwt_access'] = ''
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Cookie "jwt_access" cannot be empty.'
        )

        settings.DJWTO_MODE = 'TWO-COOKIES'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Cookie "jwt_access_token" cannot be empty.'
        )

        settings.DJWTO_MODE = 'invalid setting'
        with pytest.raises(ImproperlyConfigured) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Value of `settings.DJWTO_MODE` is invalid. Expected either "JSON", '
            '"ONE-COOKIE" or "TWO-COOKIES". Received "invalid setting" instead.'
        )

        request = rf.post('', {'jwt_type': 'invalid type'})
        settings.DJWTO_MODE = 'ONE-COOKIE'
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Input data "jwt_type" must be either "access" or "refresh". Got '
            '"invalid type" instead.'
        )

        settings.DJWTO_REFRESH_COOKIE_PATH = '/api/tokens/refresh'
        settings.DJWTO_MODE = 'TWO-COOKIES'
        request = rf.post('', {'jwt_type': 'refresh'})
        with pytest.raises(JWTValidationError) as exec_info:
            _ = auth.get_raw_token_from_request(request)
        assert exec_info.value.args[0] == (
            'Refresh cookie is only sent in path "/api/tokens/refresh". '
            'Requested path was: /.'
        )

    def test_get_raw_token_from_request(self, rf, settings):
        request = rf.post('')
        expected = 'abc.def.ghi'
        request.META['HTTP_AUTHORIZATION'] = 'Authorization: Bearer abc.def.ghi'
        token = auth.get_raw_token_from_request(request)
        assert token == expected

        settings.DJWTO_MODE = 'ONE-COOKIE'
        request.COOKIES['jwt_access'] = expected
        token = auth.get_raw_token_from_request(request)
        assert token == expected

        settings.DJWTO_MODE = 'TWO-COOKIES'
        request.COOKIES['jwt_access_token'] = expected
        token = auth.get_raw_token_from_request(request)
        assert token == expected

        request = rf.post('', {'jwt_type': 'refresh'})
        settings.DJWTO_MODE = 'ONE-COOKIE'
        request.COOKIES['jwt_refresh'] = expected
        token = auth.get_raw_token_from_request(request)
        assert token == expected

        settings.DJWTO_MODE = 'ONE-COOKIE'
        token = auth.get_raw_token_from_request(request)
        assert token == expected


class TestJWTAuthenticate:
    def test_jwt_authenticate(self, monkeypatch):
        get_mock = mock.Mock()
        get_mock.return_value = 'token'

        decode_mock = mock.Mock()
        decode_mock.return_value = 'validated'
        monkeypatch.setattr('djwto.authentication.get_raw_token_from_request', get_mock)
        monkeypatch.setattr('djwto.authentication.tokens.decode_token', decode_mock)

        result = auth.jwt_authenticate('request')
        assert result == 'validated'
        assert get_mock.called_once_with('request')
        assert decode_mock.called_once_with('token')
