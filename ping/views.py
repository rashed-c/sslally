from django.shortcuts import render
from django.http.response import HttpResponse
from modules.icmplib import *

# Create your views here.


def home(request):
    return render(request, 'polls/ping-home.html')

def do_ping(request):
    website = request.GET.get('website_port')
    host = ping(website, count=5, interval=0.2, privileged=True)
    print(host)
    return render(request, 'polls/ping-result.html', {'pinginfo':host})