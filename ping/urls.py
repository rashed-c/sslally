from django.urls import path

from . import views

urlpatterns = [
    path('', views.home),
    path('result/', views.do_ping, name='do_ping'),
]
