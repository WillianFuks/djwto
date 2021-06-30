import djwto.authentication as auth  # type: ignore
from django.views import View
from django.utils.decorators import method_decorator
from django.http.response import HttpResponse


class ProtectedView(View):
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @method_decorator(auth.jwt_login_required)
    def get(
        self,
        request,
        *args,
        **kwargs
    ):
        refresh_claims = request.payload
        print(refresh_claims)
        return HttpResponse('worked!')


class PermsProtectedView(View):
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_perm_required(['perm1']))
    def get(
        self,
        request,
        *args,
        **kwargs
    ):
        refresh_claims = request.payload
        print(refresh_claims)
        return HttpResponse('perms also worked!')
