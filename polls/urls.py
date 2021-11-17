from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('result/', views.result, name='result'),
    path('cipher_results/', views.get_cipher_suites, name='cipher_results'),
]