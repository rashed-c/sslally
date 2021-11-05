from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from modules.icmplib import *
from ratelimit.decorators import ratelimit

# Create your views here.

@ratelimit(key='ip', rate='1/m')
def home(request):
    return render(request, 'polls/ping-home.html')

@ratelimit(key='ip', rate='1/s')
def do_ping(request):
    website = request.GET.get('website_port')
    try:
        host = ping(website, count=1, interval=1, privileged=False, payload_size=32)
        if(host.packet_loss != 1.0):
            result = ("Reply from " + host.address + ":  bytes=32"+"  time=" + str(host.max_rtt))
        else:
            result = "Request timed out"
        return HttpResponse(result)
    except:
        print("Hi")
    
    