from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('result/', views.result, name='result'),
    path('test/', views.test, name='test'),
]