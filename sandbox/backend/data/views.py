import djwto.authentication as auth
from django.views import View
from django.utils.decorators import method_decorator
from django.http.response import JsonResponse, HttpResponse


class ProtectedDataView(View):
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @method_decorator(auth.jwt_login_required)
    @method_decorator(auth.jwt_perm_required(['auth.can_view_data']))
    def post(self, request, *args, **kwargs):
        refresh_claims = request.payload
        print(refresh_claims, '\n')
        data = {"data": [{"f1": 0}, {"f1": 1}]}
        return JsonResponse(data)


class OpenDataView(View):
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        data = open('data/templates/html.tmpl').read()
        return HttpResponse(data)
