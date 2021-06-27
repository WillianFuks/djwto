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

import os
from datetime import timedelta
from typing import List, Optional, Union

from typing_extensions import Literal

# Refence for each claim: https://tools.ietf.org/html/rfc7519#page-9
DJWTO_ISS_CLAIM: Optional[str] = None
DJWTO_SUB_CLAIM: Optional[str] = None
DJWTO_AUD_CLAIM: Optional[Union[List[str], str]] = None
DJWTO_IAT_CLAIM: bool = True
DJWTO_JTI_CLAIM: bool = True
DJWTO_ALLOW_REFRESH_UPDATE: bool = True

DJWTO_ACCESS_TOKEN_LIFETIME = timedelta(minutes=5)
DJWTO_REFRESH_TOKEN_LIFETIME = timedelta(days=1)
DJWTO_NBF_LIFETIME: Optional[timedelta] = timedelta(minutes=0)
DJWTO_SIGNING_KEY: str = os.environ['DJWTO_SIGNING_KEY']
# Only set if Algorithm uses asymetrical signing.
DJWTO_VERIFYING_KEY: Optional[str] = None
DJWTO_ALGORITHM: str = 'HS256'
DJWTO_MODE: Literal['JSON', 'ONE-COOKIE', 'TWO-COOKIES'] = 'JSON'
DJWTO_REFRESH_COOKIE_PATH: Optional[str] = '/api/token/refresh'
DJWTO_SAME_SITE: Optional[str] = 'Lax'
DJWTO_CSRF: bool = True
