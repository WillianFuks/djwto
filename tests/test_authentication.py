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

from djwto.authenticate import default_user_authenticate


@pytest.mark.django_db
class TestDefaultAuthenticator:
    def test_default_user_authenticate(self, rf):
        request = rf.post('', {'username': 'alice', 'password': 'pass'})
        user, errors = default_user_authenticate(request)
        assert user.username == 'alice'
        assert errors == {'errors': {}}

    def test_default_user_authenticator_invalid_data(self, rf):
        request = rf.post('', {'username': '', 'password': 'pass'})
        user, errors = default_user_authenticate(request)
        assert user is None
        assert errors == {'errors': {'username': ['This field is required.']}}

        request = rf.post('', {'username': 'alice', 'password': 'wrong pass'})
        user, errors = default_user_authenticate(request)
        assert user is None
        assert errors == {'errors': {'__all__': [
            'Please enter a correct username and '
            'password. Note that both fields may be case-sensitive.'
        ]}}
