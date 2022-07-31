from django.urls import path, include

from .views import ProtectedDataView


urlpatterns = [
    path('', ProtectedDataView.as_view()),
]
