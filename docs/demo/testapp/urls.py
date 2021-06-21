from django.urls import path
from .views import ProtectedView, PermsProtectedView


urlpatterns = [
    path('protect/', ProtectedView.as_view(), name='protect'),
    path('perms_protect/', PermsProtectedView.as_view(), name='perms_protect')
]
