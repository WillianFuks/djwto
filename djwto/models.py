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


from django.db import models


class JWTBlacklist(models.Model):
    jti = models.CharField(max_length=255, db_index=True, unique=True, null=False,
                           blank=False)
    token = models.TextField(db_index=True, null=True)
    expires = models.DateTimeField(db_index=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):  # pragma: no cover
        created_at_str = (
            self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        )
        expires_str = (
            self.expires.strftime("%Y-%m-%d %H:%M:%S") if self.expires else None
        )
        return (
            f'Token jti is: {self.jti}, {"Created at " if created_at_str else None}'
            f'{created_at_str}'
            f'{" and expires at " if expires_str else None}{expires_str}.'
        )

    @staticmethod
    def is_blacklisted(jti: str):
        """
        Checks if token is already blacklisted.

        Arguments
        ---------
          jti: str
              JWT token format.

        Returns
        -------
          bool
              If `True` then token already exists on db.

        Raises
        ------
        """
        return JWTBlacklist.objects.filter(jti=jti).exists()
