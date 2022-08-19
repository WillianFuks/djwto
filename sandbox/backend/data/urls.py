from django.urls import path, include

from .views import ProtectedDataView, OpenDataView


urlpatterns = [
    path('', ProtectedDataView.as_view()),
    path('opendata', OpenDataView.as_view()),
]
