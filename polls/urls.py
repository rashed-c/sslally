from django.urls import path

from . import views

urlpatterns = [
    path('', views.home),
    path('result/', views.result, name='result'),
    path('ssl2_0/', views.get_ssl_2_0, name='get_ssl_2_0'),
    path('ssl3_0/', views.get_ssl_3_0, name='get_ssl_3_0'),
    path('tls1_0/', views.get_tls_1_0, name='get_tls_1_0'),
    path('tls1_1/', views.get_tls_1_1, name='get_tls_1_1'),
    path('tls1_2/', views.get_tls_1_2, name='get_tls_1_2'),
    path('tls1_3/', views.get_tls_1_3, name='get_tls_1_3'),
]