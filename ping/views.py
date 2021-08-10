from django.shortcuts import render
from django.http.response import HttpResponse
from modules.icmplib import *

# Create your views here.


def home(request):

    host = ping('8.8.8.8', count=10, interval=0.2, privileged=True)
    print(host)
    return render(request, 'polls/ping-result.html', {'pinginfo':host})

