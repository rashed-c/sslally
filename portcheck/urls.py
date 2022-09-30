from django.urls import path

from . import views

urlpatterns = [
    path('', views.home),
    path('status/', views.get_port_status, name='port_status'),
]
