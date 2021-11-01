from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.icmplib import *

# Create your views here.


def home(request):
    return render(request, 'polls/ping-home.html')

def do_ping(request):
    website = request.GET.get('website_port')
    ping_result = []
    host = ping(website, count=1, interval=1, privileged=False, payload_size=32)
    result = ("Reply from " + host.address + ":  bytes=32"+"  time=" + str(host.max_rtt))
    print(result)
    return HttpResponse(result)
    