"""sslally_site URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django import urls
from django.contrib import admin
from django.urls import include, path
from django.views.generic import TemplateView


urlpatterns = [
    path('', TemplateView.as_view(template_name="polls/home.html"), name="home"),
    path('theme/', TemplateView.as_view(template_name="base.html")),
    path('traceroute/', TemplateView.as_view(template_name="polls/traceroute-home.html")),
    path('ssl/', include('polls.urls')),
    path('polls/', include('polls.urls')),
    path('ping/', include('ping.urls')),
    path('dig/', include('dig.urls')),
    path('portcheck/', include('portcheck.urls')),
    path('monitor/', include('ssl_monitor.urls')),
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),]
