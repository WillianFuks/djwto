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
from importlib import reload

import jwt as pyjwt
import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestURLs:
    sign_key = 'test'

    def test_login(self, client):
        r = client.post(reverse('login'), {'username': 'alice', 'password': 'pass'})
        assert r.status_code == 200
        data = r.json()
        assert 'refresh' in data
        assert 'access' in data

    def test_logout(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = True
        settings.DJWTO_SIGNING_KEY = self.sign_key
        expected_payload = {'jti': '2', 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)

        client.cookies['jwt_refresh'] = expected_jwt
        client.cookies['jwt_access'] = 'access jwt'
        r = client.post(reverse('logout'), {'jwt_type': 'refresh'})
        assert r.status_code == 200
        assert r.content == b'{"msg": "Token successfully blacklisted."}'

    def test_validate_access(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_CSRF = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        client.cookies['jwt_refresh'] = 'refresh jwt'
        client.cookies['jwt_access'] = expected_jwt
        r = client.post(reverse('validate_access'))
        assert r.status_code == 200
        assert r.content == b'{"msg": "Token is valid"}'

    def test_validate_refresh(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_CSRF = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        client.cookies['jwt_refresh'] = expected_jwt
        client.cookies['jwt_access'] = 'access jwt'
        r = client.post(reverse('validate_access'), {'jwt_type': 'refresh'})
        assert r.status_code == 200
        assert r.content == b'{"msg": "Token is valid"}'

    def test_refresh_access(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_CSRF = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        client.cookies['jwt_refresh'] = expected_jwt
        client.cookies['jwt_access'] = expected_jwt
        r = client.post(reverse('refresh_access'), {'jwt_type': 'refresh'})
        assert r.status_code == 200
        assert r.content == b'{"msg": "Access token successfully refreshed."}'

    def test_update_refresh(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_CSRF = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        client.cookies['jwt_refresh'] = expected_jwt
        client.cookies['jwt_access'] = expected_jwt
        r = client.post(reverse('update_refresh'), {'jwt_type': 'refresh'})
        assert r.status_code == 200
        assert r.content == b'{"msg": "Refresh token successfully updated."}'

    def test_update_refresh_set_False(self, client, settings):
        settings.DJWTO_MODE = 'ONE-COOKIE'
        settings.DJWTO_IAT_CLAIM = False
        settings.DJWTO_JTI_CLAIM = False
        settings.DJWTO_CSRF = False
        settings.DJWTO_SIGNING_KEY = self.sign_key
        exp = datetime.now() + timedelta(days=1)
        expected_payload = {'exp': exp, 'user': {'username': 'alice', 'id': 1}}
        expected_jwt = pyjwt.encode(expected_payload, self.sign_key)
        settings.DJWTO_ALLOW_REFRESH_UPDATE = False

        import djwto.urls as urls
        reload(urls)

        client.cookies['jwt_refresh'] = expected_jwt
        client.cookies['jwt_access'] = expected_jwt
        r = client.post(reverse('update_refresh'), {'jwt_type': 'refresh'})
        assert r.content == b'{"error": "Can\'t update refresh token."}'
        assert r.status_code == 500
